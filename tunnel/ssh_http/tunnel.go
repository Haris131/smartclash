package ssh_http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
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
	mu                   sync.Mutex
	once                 sync.Once
	ctx                  context.Context
	cancel               context.CancelFunc
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
	}
	t.connectionInfoPrefix = fmt.Sprintf("[SSH-HTTP] Connection #%d", connId)
	return t
}

// SetLocalPayload sets the local payload template
func (t *Tunnel) SetLocalPayload(lPayload string) {
	t.lPayload = []byte(lPayload)
}

// SetRemotePayload sets the remote payload template
func (t *Tunnel) SetRemotePayload(rPayload string) {
	if rPayload == "" {
		rPayload = "HTTP/1.1 200 Connection Established[crlf][crlf]"
	}
	rPayload = strings.Replace(rPayload, "[crlf]", "\r\n", -1)
	t.rPayload = []byte(rPayload)
}

// SetBufferSize sets the buffer size for data transfer
func (t *Tunnel) SetBufferSize(buffSize uint64) {
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
	t.earlyPinger = enabled
}

// smartDial intelligently dials the remote address
func (t *Tunnel) smartDial(ctx context.Context) (net.Conn, error) {
	// Try to parse as host:port
	host, port, err := net.SplitHostPort(t.remoteAddrStr)
	if err != nil {
		// If not host:port format, add default port
		host = t.remoteAddrStr
		port = "80"
	}

	// Check if host is already an IP address
	if ip := net.ParseIP(host); ip != nil {
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}

	// For domain names, perform DNS lookup with timeout
	log.Debugln("%s Resolving domain: %s", t.connectionInfoPrefix, host)
	
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	resolver := &net.Resolver{
		PreferGo: true,
	}
	
	ips, err := resolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		log.Warnln("%s DNS resolution failed for %s: %v, using direct dial", 
			t.connectionInfoPrefix, host, err)
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
		}
		return dialer.DialContext(ctx, "tcp", t.remoteAddrStr)
	}
	
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", host)
	}
	
	// Prefer IPv4 addresses
	var selectedIP net.IP
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			selectedIP = ip.IP.To4()
			break
		}
	}
	if selectedIP == nil {
		selectedIP = ips[0].IP
	}
	
	log.Debugln("%s Resolved %s -> %s", t.connectionInfoPrefix, host, selectedIP.String())
	
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(selectedIP.String(), port))
}

// Start starts the tunnel data transfer
func (t *Tunnel) Start() {
	defer t.cancel()
	defer t.closeConnection(t.lConn)

	// Create context with timeout for dialing
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Dial remote connection
	var err error
	t.rConn, err = t.smartDial(dialCtx)
	if err != nil {
		log.Errorln("%s Cannot dial remote connection: %s", t.connectionInfoPrefix, err)
		return
	}
	defer t.closeConnection(t.rConn)

	log.Infoln("%s Opened %s >> %s", t.connectionInfoPrefix, t.lConn.RemoteAddr(), t.remoteAddrStr)

	// Start bidirectional data forwarding
	go t.handleForwardData(t.lConn, t.rConn)
	go t.handleForwardData(t.rConn, t.lConn)
	
	// Wait for completion
	<-t.errSig
	log.Infoln("%s Closed (%d bytes sent, %d bytes received)", 
		t.connectionInfoPrefix, t.bytesSent, t.bytesReceived)
}

// Cancel cancels the tunnel context
func (t *Tunnel) Cancel() {
	t.cancel()
}

// closeConnection safely closes a connection
func (t *Tunnel) closeConnection(conn net.Conn) {
	if conn != nil {
		if err := conn.Close(); err != nil {
			log.Debugln("%s Cannot close connection: %s", t.connectionInfoPrefix, err)
		}
	}
}

// err signals an error and initiates cleanup
func (t *Tunnel) err() {
	t.once.Do(func() {
		t.errSig <- true
		t.erred = true
		t.cancel()
	})
}

// handleForwardData handles data forwarding between two connections
func (t *Tunnel) handleForwardData(src, dst net.Conn) {
	isLocal := src == t.lConn
	buffer := make([]byte, t.buffSize)

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			n, err := src.Read(buffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) ||
					strings.Contains(err.Error(), "use of closed network connection") {
					log.Debugln("%s Connection closed normally: %s", t.connectionInfoPrefix, err)
				} else if err.Error() == "EOF" {
					log.Debugln("%s EOF reached", t.connectionInfoPrefix)
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
			if isLocal {
				t.handleOutboundData(src, dst, &connBuff)
			} else {
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
	if t.lInitialized {
		return
	}

	log.Infoln("%s %s >> %s >> %s", t.connectionInfoPrefix, 
		src.RemoteAddr(), t.conn.LocalAddr(), dst.RemoteAddr())

	// Parse HTTP CONNECT request
	var respArr []string
	buffScanner := bufio.NewScanner(strings.NewReader(string(*connBuff)))
	for buffScanner.Scan() {
		respArr = append(respArr, buffScanner.Text())
	}

	if len(respArr) > 0 && strings.Contains(respArr[0], "CONNECT ") {
		parts := strings.Split(respArr[0], " ")
		if len(parts) >= 2 {
			hostPort := parts[1]
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
				lPayloadStr = strings.Replace(lPayloadStr, "[host]", t.sHost.HostName, -1)
				lPayloadStr = strings.Replace(lPayloadStr, "[host_port]", 
					fmt.Sprintf("%s:%d", t.sHost.HostName, t.sHost.Port), -1)
				lPayloadStr = strings.Replace(lPayloadStr, "[crlf]", "\r\n", -1)
				lPayloadStr = strings.Replace(lPayloadStr, "[crlf*2]", "\r\n\r\n", -1)
				lPayloadStr = strings.Replace(lPayloadStr, "[lf]", "\n", -1)
				lPayloadStr = strings.Replace(lPayloadStr, "[cr]", "\r", -1)
				lPayloadStr = strings.Replace(lPayloadStr, "[protocol]", "HTTP/1.1", -1)
				lPayloadStr = strings.Replace(lPayloadStr, "[ua]", "Dalvik/2.1.0", -1)
				t.lPayload = []byte(lPayloadStr)
			}
		}

		// Early ping if enabled
		if t.earlyPinger && t.sHost.HostName != "" && t.sHost.HostName != "localhost" {
			go t.doPing(t.sHost.HostName)
		}
		
		// Apply local payload
		if len(t.lPayload) > 0 {
			*connBuff = t.lPayload
			log.Debugln("%s Outbound payload: %s", t.connectionInfoPrefix, string(*connBuff))
		}
	}

	t.lInitialized = true
}

// handleInboundData processes inbound (server -> client) data
func (t *Tunnel) handleInboundData(src, dst net.Conn, connBuff *[]byte) {
	if t.rInitialized {
		return
	}

	log.Infoln("%s %s << %s << %s", t.connectionInfoPrefix, 
		dst.RemoteAddr(), t.conn.LocalAddr(), src.RemoteAddr())

	var respArr []string
	buffScanner := bufio.NewScanner(strings.NewReader(string(*connBuff)))
	for buffScanner.Scan() {
		respArr = append(respArr, buffScanner.Text())
	}
	
	// Handle WebSocket upgrade responses
	if len(respArr) > 0 && strings.Contains(respArr[0], " 101 ") {
		respArr[0] = strings.Replace(string(t.rPayload), "\r\n", "", -1)
	}

	// Apply remote payload
	if len(respArr) > 0 {
		*connBuff = []byte(strings.Join(respArr, "\r\n") + "\r\n")
		log.Debugln("%s Inbound payload: %s", t.connectionInfoPrefix, string(*connBuff))
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
	go func() {
		resp, err := client.Get("http://" + host)
		if err != nil {
			log.Debugln("%s Ping %s failed: %v", t.connectionInfoPrefix, host, err)
			return
		}
		resp.Body.Close()
	}()
}