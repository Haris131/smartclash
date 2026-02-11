package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/ssh_http"

	"github.com/metacubex/randv2"
	"golang.org/x/crypto/ssh"
)

type Ssh struct {
	*Base

	option           *SshOption
	config           *ssh.ClientConfig
	client           *ssh.Client
	cMutex           sync.Mutex
	
	// HTTP Tunnel fields
	httpTunnelServer  *ssh_http.Server
	httpTunnelAddr    string
	httpTunnelStarted bool
	httpTunnelMutex   sync.Mutex
	
	// Connection pool for HTTP tunnel connections
	connPool         *connPool
	
	// Graceful shutdown
	shutdownChan     chan struct{}
	shutdownOnce     sync.Once
}

type SshOption struct {
	BasicOption
	Name                 string   `proxy:"name"`
	Server               string   `proxy:"server"`
	Port                 int      `proxy:"port"`
	UserName             string   `proxy:"username"`
	Password             string   `proxy:"password,omitempty"`
	PrivateKey           string   `proxy:"private-key,omitempty"`
	PrivateKeyPassphrase string   `proxy:"private-key-passphrase,omitempty"`
	HostKey              []string `proxy:"host-key,omitempty"`
	HostKeyAlgorithms    []string `proxy:"host-key-algorithms,omitempty"`
	
	// HTTP Tunnel configuration
	EnableHTTP           bool     `proxy:"http,omitempty"`
	Tunnel               struct {
		Proxy struct {
			IP   string `proxy:"ip"`
			Port int    `proxy:"port"`
		} `proxy:"proxy"`
		Payload       string `proxy:"payload,omitempty"`
		RemotePayload string `proxy:"remote-payload,omitempty"`
		BufferSize    uint64 `proxy:"buffer-size,omitempty"`
	} `proxy:"tunnel,omitempty"`
}

// connPool manages reusable SSH connections for HTTP tunnel mode
type connPool struct {
	mu    sync.Mutex
	conns map[string]*ssh.Client
}

func newConnPool() *connPool {
	return &connPool{
		conns: make(map[string]*ssh.Client),
	}
}

func (p *connPool) get(key string) (*ssh.Client, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	client, ok := p.conns[key]
	if ok && client != nil {
		// Test connection with timeout
		timeout := time.After(2 * time.Second)
		result := make(chan error, 1)
		
		go func() {
			_, _, err := client.SendRequest("keepalive", false, nil)
			result <- err
		}()
		
		select {
		case err := <-result:
			if err == nil {
				return client, true
			}
		case <-timeout:
			// Connection timeout
		}
		
		// Remove dead connection
		delete(p.conns, key)
	}
	return nil, false
}

func (p *connPool) put(key string, client *ssh.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Remove old connection if exists
	if oldClient, ok := p.conns[key]; ok && oldClient != nil {
		oldClient.Close()
	}
	p.conns[key] = client
}

func (p *connPool) remove(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if client, ok := p.conns[key]; ok && client != nil {
		client.Close()
	}
	delete(p.conns, key)
}

func (p *connPool) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, client := range p.conns {
		if client != nil {
			client.Close()
		}
		delete(p.conns, key)
	}
}

// httpTunnelConn wraps connections for proper cleanup in HTTP tunnel mode
type httpTunnelConn struct {
	net.Conn
	ssh     *ssh.Client
	tunnel  net.Conn
	closer  *Ssh
	connKey string
}

func (c *httpTunnelConn) Close() error {
	var errs []error
	
	if c.tunnel != nil {
		if err := c.tunnel.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tunnel close: %w", err))
		}
	}
	
	if c.Conn != nil {
		if err := c.Conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("connection close: %w", err))
		}
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("multiple errors closing connection: %v", errs)
	}
	return nil
}

func (s *Ssh) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	select {
	case <-s.shutdownChan:
		return nil, fmt.Errorf("SSH proxy is shutting down")
	default:
	}

	// Choose connection method based on configuration
	if s.option.EnableHTTP {
		// SSH via HTTP Tunnel
		return s.dialViaHTTPTunnel(ctx, metadata)
	}
	
	// Direct SSH connection (original behavior)
	client, err := s.connect(ctx, s.addr)
	if err != nil {
		return nil, err
	}
	
	c, err := client.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}

	return NewConn(c, s), nil
}

// startHTTPTunnelServer starts a local HTTP tunnel server for SSH-over-HTTP
func (s *Ssh) startHTTPTunnelServer() (string, error) {
	s.httpTunnelMutex.Lock()
	defer s.httpTunnelMutex.Unlock()
	
	// Check if server is already running
	if s.httpTunnelStarted && s.httpTunnelServer != nil && s.httpTunnelServer.IsRunning() {
		return s.httpTunnelAddr, nil
	}
	
	// Reset state if server was marked as started but not running
	if s.httpTunnelStarted {
		s.httpTunnelStarted = false
		s.httpTunnelServer = nil
	}
	
	// Validate tunnel configuration
	if s.option.Tunnel.Proxy.IP == "" || s.option.Tunnel.Proxy.Port == 0 {
		return "", fmt.Errorf("HTTP tunnel proxy configuration is required when http is enabled")
	}
	
	// Format remote address
	remoteAddr := fmt.Sprintf("%s:%d", s.option.Tunnel.Proxy.IP, s.option.Tunnel.Proxy.Port)
	
	// Create tunnel configuration
	config := &ssh_http.Config{
		LocalAddress:  "", // Use random port
		RemoteAddress: remoteAddr,
		LocalPayload:  s.option.Tunnel.Payload,
		RemotePayload: s.option.Tunnel.RemotePayload,
		BufferSize:    s.option.Tunnel.BufferSize,
	}
	
	// Set default buffer size if not specified
	if config.BufferSize == 0 {
		config.BufferSize = 8192
	}
	
	// Create and start HTTP tunnel server
	s.httpTunnelServer = ssh_http.NewServer(config)
	localAddr, err := s.httpTunnelServer.Start()
	if err != nil {
		return "", fmt.Errorf("failed to start HTTP tunnel server: %w", err)
	}
	
	s.httpTunnelAddr = localAddr
	s.httpTunnelStarted = true
	log.Infoln("[SSH-HTTP] Tunnel server started for SSH proxy %s on %s -> %s", 
		s.name, localAddr, remoteAddr)
	
	return localAddr, nil
}

// dialViaHTTPTunnel establishes SSH connection through HTTP CONNECT tunnel
func (s *Ssh) dialViaHTTPTunnel(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	// Start HTTP tunnel server if not already running
	localAddr, err := s.startHTTPTunnelServer()
	if err != nil {
		return nil, fmt.Errorf("failed to start HTTP tunnel server: %w", err)
	}
	
	// Use connection pooling for tunnel connections
	connKey := fmt.Sprintf("%s:%s", localAddr, s.addr)
	
	// Try to get existing connection from pool
	if client, ok := s.connPool.get(connKey); ok {
		sshConn, err := client.DialContext(ctx, "tcp", metadata.RemoteAddress())
		if err == nil {
			return NewConn(sshConn, s), nil
		}
		// Remove dead connection from pool
		s.connPool.remove(connKey)
	}
	
	// Connect to local HTTP tunnel server with timeout
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HTTP tunnel server: %w", err)
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	
	// Send HTTP CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", 
		s.addr, s.addr)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}
	
	// Read HTTP response with timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %w", err)
	}
	
	// Safe HTTP response parsing
	response := strings.ToUpper(string(buf[:n]))
	if !strings.Contains(response, "200") && !strings.Contains(response, "CONNECTION ESTABLISHED") {
		return nil, fmt.Errorf("HTTP tunnel error: %s", response)
	}
	
	// Setup context for connection
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}
	
	// Establish SSH connection through tunnel
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, s.addr, s.config)
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH connection through HTTP tunnel: %w", err)
	}
	
	client := ssh.NewClient(clientConn, chans, reqs)
	
	// Store connection in pool
	s.connPool.put(connKey, client)
	
	// Dial target through SSH
	sshConn, err := client.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		s.connPool.remove(connKey)
		return nil, fmt.Errorf("failed to dial target through SSH: %w", err)
	}
	
	// Wrap connection for proper cleanup
	wrappedConn := &httpTunnelConn{
		Conn:   sshConn,
		ssh:    client,
		tunnel: conn,
		closer: s,
		connKey: connKey,
	}
	
	return NewConn(wrappedConn, s), nil
}

func (s *Ssh) connect(ctx context.Context, addr string) (client *ssh.Client, err error) {
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	
	select {
	case <-s.shutdownChan:
		return nil, fmt.Errorf("SSH proxy is shutting down")
	default:
	}
	
	// Return existing client if available and alive
	if s.client != nil {
		// Test connection with timeout
		timeout := time.After(2 * time.Second)
		result := make(chan error, 1)
		
		go func() {
			_, _, err := s.client.SendRequest("keepalive", false, nil)
			result <- err
		}()
		
		select {
		case err := <-result:
			if err == nil {
				return s.client, nil
			}
		case <-timeout:
		}
		// Connection is dead, close it
		s.client.Close()
		s.client = nil
	}
	
	c, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil && c != nil {
			c.Close()
		}
	}()

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(c, addr, s.config)
	if err != nil {
		return nil, err
	}
	client = ssh.NewClient(clientConn, chans, reqs)

	s.client = client

	go func() {
		_ = client.Wait()
		s.cMutex.Lock()
		defer s.cMutex.Unlock()
		if s.client == client {
			s.client = nil
		}
	}()

	return client, nil
}

// ProxyInfo implements C.ProxyAdapter
func (s *Ssh) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter with graceful shutdown
func (s *Ssh) Close() error {
	s.shutdownOnce.Do(func() {
		close(s.shutdownChan)
	})
	
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	
	var errs []error
	
	// Clear connection pool
	if s.connPool != nil {
		s.connPool.clear()
	}
	
	// Stop HTTP tunnel server if running
	if s.httpTunnelServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		
		done := make(chan error, 1)
		go func() {
			done <- s.httpTunnelServer.Stop()
		}()
		
		select {
		case err := <-done:
			if err != nil {
				errs = append(errs, fmt.Errorf("HTTP tunnel server stop: %w", err))
			} else {
				log.Infoln("[SSH-HTTP] Tunnel server stopped for SSH proxy %s", s.name)
			}
		case <-ctx.Done():
			errs = append(errs, fmt.Errorf("HTTP tunnel server stop timeout"))
		}
		
		s.httpTunnelServer = nil
		s.httpTunnelStarted = false
	}
	
	// Close SSH client
	if s.client != nil {
		if err := s.client.Close(); err != nil {
			errs = append(errs, fmt.Errorf("SSH client close: %w", err))
		}
		s.client = nil
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("errors closing SSH proxy: %v", errs)
	}
	return nil
}

func NewSsh(option SshOption) (*Ssh, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	config := ssh.ClientConfig{
		User:              option.UserName,
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: option.HostKeyAlgorithms,
		Timeout:           10 * time.Second,
	}

	if option.PrivateKey != "" {
		var b []byte
		var err error
		if strings.Contains(option.PrivateKey, "PRIVATE KEY") {
			b = []byte(option.PrivateKey)
		} else {
			path := C.Path.Resolve(option.PrivateKey)
			if !C.Path.IsSafePath(path) {
				return nil, C.Path.ErrNotSafePath(path)
			}
			b, err = os.ReadFile(path)
			if err != nil {
				return nil, err
			}
		}
		var pKey ssh.Signer
		if option.PrivateKeyPassphrase != "" {
			pKey, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(option.PrivateKeyPassphrase))
		} else {
			pKey, err = ssh.ParsePrivateKey(b)
		}
		if err != nil {
			return nil, err
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(pKey))
	}

	if option.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(option.Password))
	}

	if len(option.HostKey) != 0 {
		keys := make([]ssh.PublicKey, len(option.HostKey))
		for i, hostKey := range option.HostKey {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
			if err != nil {
				return nil, fmt.Errorf("parse host key failed: %w", err)
			}
			keys[i] = key
		}
		config.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			serverKey := key.Marshal()
			for _, hostKey := range keys {
				if bytes.Equal(serverKey, hostKey.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("host key mismatch, server sent: %s %s", 
				key.Type(), base64.StdEncoding.EncodeToString(serverKey))
		}
	}

	// Randomize SSH client version
	version := "SSH-2.0-OpenSSH_"
	if randv2.IntN(2) == 0 {
		version += "7." + strconv.Itoa(randv2.IntN(10))
	} else {
		version += "8." + strconv.Itoa(randv2.IntN(9))
	}
	config.ClientVersion = version

	// Create outbound instance
	outbound := &Ssh{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Ssh,
			pdName: option.ProviderName,
			udp:    false,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option:       &option,
		config:       &config,
		connPool:     newConnPool(),
		shutdownChan: make(chan struct{}),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
