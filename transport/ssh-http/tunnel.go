package ssh_http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// DNS cache untuk menyimpan hasil resolusi domain
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
}

type dnsCacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
	createdAt time.Time
}

var (
	globalDNSCache = &dnsCache{
		entries: make(map[string]*dnsCacheEntry),
	}
	// TTL cache: 5 menit untuk hasil sukses, 30 detik untuk hasil gagal
	cacheTTLSuccess = 5 * time.Minute
	cacheTTLFailure = 30 * time.Second
)

// Tunnel manages a single HTTP CONNECT tunnel connection
type Tunnel struct {
	connectionInfoPrefix string
	conn                 net.Conn
	lConn                net.Conn
	rConn                net.Conn
	lAddr                *net.TCPAddr
	remoteAddrStr        string
	sHost                Host
	earlyPinger          bool
	lPayload             []byte
	rPayload             []byte
	buffSize             uint64
	lInitialized         bool
	rInitialized         bool
	bytesReceived        uint64
	bytesSent            uint64
	erred                bool
	errSig               chan bool
	connId               uint64
	wsUpgradeInitialized bool
	mu                   sync.RWMutex
	once                 sync.Once
	ctx                  context.Context
	cancel               context.CancelFunc
	shutdownChan         chan struct{}
}

// Host represents a destination host
type Host struct {
	HostName string
	Port     uint64
}

// NewTunnel creates a new tunnel instance
func NewTunnel(connId uint64, conn net.Conn, lAddr *net.TCPAddr, remoteAddrStr string) *Tunnel {
	ctx, cancel := context.WithCancel(context.Background())
	t := &Tunnel{
		conn:                 conn,
		lConn:                conn,
		lAddr:                lAddr,
		remoteAddrStr:        remoteAddrStr,
		lPayload:             make([]byte, 0),
		rPayload:             make([]byte, 0),
		buffSize:             uint64(0xffff),
		lInitialized:         false,
		rInitialized:         false,
		erred:                false,
		errSig:               make(chan bool, 2),
		connId:               connId,
		wsUpgradeInitialized: false,
		earlyPinger:          false,
		ctx:                  ctx,
		cancel:               cancel,
		shutdownChan:         make(chan struct{}),
	}
	t.connectionInfoPrefix = fmt.Sprintf("[SSH-HTTP] Connection #%d", connId)
	return t
}

// SetLocalPayload sets the local payload template
func (t *Tunnel) SetLocalPayload(lPayload string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lPayload = []byte(lPayload)
}

// SetRemotePayload sets the remote payload template
func (t *Tunnel) SetRemotePayload(rPayload string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	if rPayload == "" {
		rPayload = "HTTP/1.1 200 Connection Established\r\n\r\n"
	} else {
		// Properly handle [crlf] replacement
		rPayload = strings.ReplaceAll(rPayload, "[crlf]", "\r\n")
		rPayload = strings.ReplaceAll(rPayload, "[lf]", "\n")
		rPayload = strings.ReplaceAll(rPayload, "[cr]", "\r")
	}
	t.rPayload = []byte(rPayload)
}

// SetBufferSize sets the buffer size for data transfer
func (t *Tunnel) SetBufferSize(buffSize uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if buffSize < 1024 {
		buffSize = 1024
	}
	if buffSize > 65535 {
		buffSize = 65535
	}
	t.buffSize = buffSize
}

// SetEarlyPinger enables/disables early ping feature
func (t *Tunnel) SetEarlyPinger(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.earlyPinger = enabled
}

// getCachedIPs mendapatkan IP dari cache
func getCachedIPs(host string) ([]net.IP, bool) {
	globalDNSCache.mu.RLock()
	defer globalDNSCache.mu.RUnlock()
	
	entry, exists := globalDNSCache.entries[host]
	if !exists {
		return nil, false
	}
	
	if time.Now().After(entry.expiresAt) {
		// Cache expired, hapus secara lazy
		go func() {
			globalDNSCache.mu.Lock()
			defer globalDNSCache.mu.Unlock()
			delete(globalDNSCache.entries, host)
		}()
		return nil, false
	}
	
	// Return copy of IPs to prevent modification
	ips := make([]net.IP, len(entry.ips))
	copy(ips, entry.ips)
	return ips, true
}

// cacheIPs menyimpan IP ke cache (hanya IPv4)
func cacheIPs(host string, ips []net.IP, success bool) {
	globalDNSCache.mu.Lock()
	defer globalDNSCache.mu.Unlock()
	
	// Hapus entry lama jika ada
	delete(globalDNSCache.entries, host)
	
	// Filter hanya IPv4
	var ipv4IPs []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4IPs = append(ipv4IPs, ip.To4())
		}
	}
	
	// Tentukan TTL berdasarkan keberhasilan
	ttl := cacheTTLSuccess
	if !success || len(ipv4IPs) == 0 {
		ttl = cacheTTLFailure
	}
	
	globalDNSCache.entries[host] = &dnsCacheEntry{
		ips:       ipv4IPs,
		expiresAt: time.Now().Add(ttl),
		createdAt: time.Now(),
	}
}

// resolveHostWithCache melakukan resolusi DNS dengan cache (hanya IPv4)
func (t *Tunnel) resolveHostWithCache(ctx context.Context, host string) ([]net.IP, error) {
	// Cek cache terlebih dahulu
	if ips, found := getCachedIPs(host); found {
		log.Debugln("%s Using cached DNS for %s -> %v", t.connectionInfoPrefix, host, ips)
		return ips, nil
	}
	
	log.Debugln("%s Cache miss, resolving domain (IPv4 only): %s", t.connectionInfoPrefix, host)
	
	// Resolve dengan timeout
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	resolver := &net.Resolver{
		PreferGo: true,
	}
	
	ipAddrs, err := resolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		log.Errorln("%s DNS resolution failed for %s: %v", 
			t.connectionInfoPrefix, host, err)
		// Cache hasil gagal
		cacheIPs(host, nil, false)
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	
	if len(ipAddrs) == 0 {
		err := fmt.Errorf("no IP addresses found for %s", host)
		cacheIPs(host, nil, false)
		return nil, err
	}
	
	// Konversi ke []net.IP dan filter hanya IPv4
	var ips []net.IP
	for _, ipAddr := range ipAddrs {
		if ip := ipAddr.IP.To4(); ip != nil {
			ips = append(ips, ip)
		}
	}
	
	if len(ips) == 0 {
		err := fmt.Errorf("no IPv4 addresses found for %s", host)
		log.Errorln("%s %v", t.connectionInfoPrefix, err)
		// Cache hasil gagal (tidak ada IPv4)
		cacheIPs(host, nil, false)
		return nil, err
	}
	
	// Cache hasil sukses (hanya IPv4)
	cacheIPs(host, ips, true)
	
	log.Debugln("%s Resolved %s -> %v (IPv4 only)", t.connectionInfoPrefix, host, ips)
	return ips, nil
}

// cleanupCacheMembership membersihkan cache yang sudah expired (dipanggil secara periodic)
func cleanupDNSCache() {
	globalDNSCache.mu.Lock()
	defer globalDNSCache.mu.Unlock()
	
	now := time.Now()
	for host, entry := range globalDNSCache.entries {
		if now.After(entry.expiresAt) {
			delete(globalDNSCache.entries, host)
		}
	}
}

// smartDial intelligently dials the remote address with DNS caching (IPv4 only)
func (t *Tunnel) smartDial(ctx context.Context) (net.Conn, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("%s Recovered from panic in smartDial: %v", t.connectionInfoPrefix, r)
		}
	}()
	
	// Try to parse as host:port
	host, port, err := net.SplitHostPort(t.remoteAddrStr)
	if err != nil {
		// If not host:port format, add default port
		host = t.remoteAddrStr
		port = "80"
	}

	// Check if host is already an IP address
	if ip := net.ParseIP(host); ip != nil {
		// Hanya izinkan IPv4
		if ip.To4() == nil {
			return nil, fmt.Errorf("IPv6 addresses are not supported: %s", host)
		}
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}

	// For domain names, use DNS cache (IPv4 only)
	ips, err := t.resolveHostWithCache(ctx, host)
	if err != nil {
		return nil, err
	}
	
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found for %s", host)
	}
	
	// Coba koneksi ke semua IP (semua sudah IPv4)
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	
	// Coba semua IP yang tersedia
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), port)
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			log.Debugln("%s Connected via IPv4: %s", t.connectionInfoPrefix, ip.String())
			return conn, nil
		}
		log.Debugln("%s IPv4 %s failed: %v", t.connectionInfoPrefix, ip.String(), err)
	}
	
	return nil, fmt.Errorf("failed to connect to any IPv4 address for %s", host)
}

// Start starts the tunnel data transfer
func (t *Tunnel) Start() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("%s Recovered from panic in Tunnel.Start: %v", t.connectionInfoPrefix, r)
		}
		t.cancel()
		close(t.shutdownChan)
	}()
	defer t.closeConnection(t.lConn)

	// Create context with timeout for dialing
	dialCtx, cancel := context.WithTimeout(t.ctx, 15*time.Second)
	defer cancel()

	// Dial remote connection with retry logic
	var err error
	var retryCount int
	const maxRetries = 2
	
	for retryCount <= maxRetries {
		t.rConn, err = t.smartDial(dialCtx)
		if err == nil {
			break
		}
		
		retryCount++
		if retryCount > maxRetries {
			log.Errorln("%s Cannot dial remote connection after %d attempts: %s", 
				t.connectionInfoPrefix, maxRetries, err)
			
			// Send error response to client
			if t.lConn != nil {
				errorResponse := "HTTP/1.1 502 Bad Gateway\r\n\r\n"
				t.lConn.Write([]byte(errorResponse))
			}
			return
		}
		
		log.Debugln("%s Retry %d/%d connecting to %s", 
			t.connectionInfoPrefix, retryCount, maxRetries, t.remoteAddrStr)
		time.Sleep(time.Duration(retryCount) * time.Second)
	}

	defer t.closeConnection(t.rConn)

	log.Infoln("%s Opened %s >> %s", t.connectionInfoPrefix, t.lConn.RemoteAddr(), t.remoteAddrStr)

	// Start bidirectional data forwarding
	wg := &sync.WaitGroup{}
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		t.handleForwardData(t.lConn, t.rConn)
	}()
	
	go func() {
		defer wg.Done()
		t.handleForwardData(t.rConn, t.lConn)
	}()
	
	// Wait for completion
	<-t.errSig
	wg.Wait()
	
	log.Infoln("%s Closed (%d bytes sent, %d bytes received)", 
		t.connectionInfoPrefix, t.bytesSent, t.bytesReceived)
}

// Cancel cancels the tunnel context
func (t *Tunnel) Cancel() {
	t.cancel()
	close(t.shutdownChan)
}

// closeConnection safely closes a connection
func (t *Tunnel) closeConnection(conn net.Conn) {
	if conn != nil {
		if err := conn.Close(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Debugln("%s Cannot close connection: %s", t.connectionInfoPrefix, err)
		}
	}
}

// err signals an error and initiates cleanup
func (t *Tunnel) err() {
	t.once.Do(func() {
		select {
		case t.errSig <- true:
		default:
		}
		t.erred = true
		t.cancel()
	})
}

// handleForwardData handles data forwarding between two connections
func (t *Tunnel) handleForwardData(src, dst net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("%s Recovered from panic in handleForwardData: %v", t.connectionInfoPrefix, r)
		}
		t.err()
	}()
	
	t.mu.RLock()
	bufferSize := t.buffSize
	t.mu.RUnlock()
	
	buffer := make([]byte, bufferSize)
	
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-t.shutdownChan:
			return
		default:
			// Set read timeout
			src.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := src.Read(buffer)
			
			if err != nil {
				if err == io.EOF {
					log.Debugln("%s EOF reached", t.connectionInfoPrefix)
					t.err()
					return
				}
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout, continue reading
					continue
				}
				if errors.Is(err, net.ErrClosed) ||
					strings.Contains(err.Error(), "use of closed network connection") {
					log.Debugln("%s Connection closed normally: %s", t.connectionInfoPrefix, err)
				} else {
					log.Errorln("%s Cannot read buffer from source: %s", t.connectionInfoPrefix, err)
				}
				t.err()
				return
			}

			if n == 0 {
				t.err()
				return
			}

			connBuff := buffer[:n]
			isLocal := src == t.lConn
			
			if isLocal && !t.lInitialized {
				t.handleOutboundData(src, dst, &connBuff)
			} else if !isLocal && !t.rInitialized {
				t.handleInboundData(src, dst, &connBuff)
			}

			_, err = dst.Write(connBuff)
			if err != nil {
				if errors.Is(err, net.ErrClosed) ||
					strings.Contains(err.Error(), "use of closed network connection") {
					log.Debugln("%s Connection closed during write: %s", t.connectionInfoPrefix, err)
				} else {
					log.Errorln("%s Cannot write buffer to destination: %s", t.connectionInfoPrefix, err)
				}
				t.err()
				return
			}

			if isLocal {
				t.bytesSent += uint64(n)
			} else {
				t.bytesReceived += uint64(n)
			}
		}
	}
}

// handleOutboundData processes outbound (client -> server) data
func (t *Tunnel) handleOutboundData(src, dst net.Conn, connBuff *[]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	if t.lInitialized {
		return
	}

	log.Infoln("%s %s >> %s >> %s", t.connectionInfoPrefix, 
		src.RemoteAddr(), t.conn.LocalAddr(), dst.RemoteAddr())

	// Parse HTTP CONNECT request
	reader := bufio.NewReader(strings.NewReader(string(*connBuff)))
	
	// Read first line
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	
	if strings.Contains(firstLine, "CONNECT ") {
		parts := strings.Split(firstLine, " ")
		if len(parts) >= 2 {
			hostPort := strings.TrimSpace(parts[1])
			sHost, sPort, err := net.SplitHostPort(hostPort)
			if err != nil {
				sHost = hostPort
				sPort = "80"
			}
			sPortParsed, err := strconv.ParseUint(sPort, 10, 64)
			if err != nil {
				sPortParsed = 80
			}

			t.sHost = Host{
				HostName: sHost,
				Port:     sPortParsed,
			}

			// Process local payload template
			if len(t.lPayload) > 0 {
				lPayloadStr := string(t.lPayload)
				lPayloadStr = strings.ReplaceAll(lPayloadStr, "[host]", t.sHost.HostName)
				lPayloadStr = strings.ReplaceAll(lPayloadStr, "[host_port]", 
					fmt.Sprintf("%s:%d", t.sHost.HostName, t.sHost.Port))
				lPayloadStr = strings.ReplaceAll(lPayloadStr, "[crlf]", "\r\n")
				lPayloadStr = strings.ReplaceAll(lPayloadStr, "[crlf*2]", "\r\n\r\n")
				lPayloadStr = strings.ReplaceAll(lPayloadStr, "[lf]", "\n")
				lPayloadStr = strings.ReplaceAll(lPayloadStr, "[cr]", "\r")
				lPayloadStr = strings.ReplaceAll(lPayloadStr, "[protocol]", "HTTP/1.1")
				lPayloadStr = strings.ReplaceAll(lPayloadStr, "[ua]", "Dalvik/2.1.0")
				t.lPayload = []byte(lPayloadStr)
			}
		}

		// Early ping if enabled
		if t.earlyPinger && t.sHost.HostName != "" && t.sHost.HostName != "localhost" {
			go t.doPing(t.sHost.HostName)
		}
		
		// Apply local payload if it's a WebSocket upgrade
		if len(t.lPayload) > 0 && strings.Contains(string(t.lPayload), "Upgrade: websocket") {
			*connBuff = t.lPayload
			log.Debugln("%s Outbound payload: %s", t.connectionInfoPrefix, string(*connBuff))
		}
	}

	t.lInitialized = true
}

// handleInboundData processes inbound (server -> client) data
func (t *Tunnel) handleInboundData(src, dst net.Conn, connBuff *[]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	if t.rInitialized {
		return
	}

	log.Infoln("%s %s << %s << %s", t.connectionInfoPrefix, 
		dst.RemoteAddr(), t.conn.LocalAddr(), src.RemoteAddr())

	// Parse response
	response := string(*connBuff)
	
	// Handle WebSocket upgrade responses
	if strings.Contains(response, " 101 ") && len(t.rPayload) > 0 {
		*connBuff = t.rPayload
		log.Debugln("%s Inbound WebSocket upgrade response", t.connectionInfoPrefix)
	}

	t.rInitialized = true
}

// doPing performs an early ping to warm up connections
func (t *Tunnel) doPing(host string) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugln("%s Ping recovered from panic: %v", t.connectionInfoPrefix, r)
		}
	}()
	
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	
	// Use goroutine to avoid blocking
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Debugln("%s Ping goroutine recovered: %v", t.connectionInfoPrefix, r)
			}
		}()
		
		resp, err := client.Get("http://" + host)
		if err != nil {
			log.Debugln("%s Ping %s failed: %v", t.connectionInfoPrefix, host, err)
			return
		}
		resp.Body.Close()
	}()
}

// init fungsi cleanup cache secara periodic
func init() {
	// Jalankan cleanup cache setiap 1 menit
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				cleanupDNSCache()
			}
		}
	}()
}
