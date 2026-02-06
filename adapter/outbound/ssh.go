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
	option              *SshOption
	config              *ssh.ClientConfig
	client              *ssh.Client
	cMutex              sync.Mutex
	httpTunnelServer    *ssh_http.Server
	httpTunnelAddr      string
	httpTunnelStarted   bool
	httpTunnelMutex     sync.Mutex
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

// DialContext implements C.ProxyAdapter
func (s *Ssh) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if s.option.EnableHTTP {
		// Start HTTP tunnel server first
		localAddr, err := s.startHTTPTunnelServer()
		if err != nil {
			return nil, fmt.Errorf("failed to start HTTP tunnel server: %w", err)
		}
		
		// Connect through HTTP tunnel
		return s.connectViaHTTPTunnel(ctx, metadata, localAddr)
	}
	
	// Direct SSH connection
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

// connectViaHTTPTunnel establishes SSH connection through HTTP CONNECT tunnel
func (s *Ssh) connectViaHTTPTunnel(ctx context.Context, metadata *C.Metadata, tunnelAddr string) (_ C.Conn, err error) {
	// Connect to local HTTP tunnel server
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", tunnelAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HTTP tunnel server: %w", err)
	}
	
	// Send HTTP CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", 
		s.addr, s.addr)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}
	
	// Read HTTP response with timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{}) // Clear deadline
	
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read HTTP response: %w", err)
	}
	
	// Check for successful response
	response := string(buf[:n])
	if !strings.Contains(response, "200") {
		conn.Close()
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
		conn.Close()
		return nil, fmt.Errorf("failed to establish SSH connection through HTTP tunnel: %w", err)
	}
	
	client := ssh.NewClient(clientConn, chans, reqs)
	
	// Dial target through SSH
	sshConn, err := client.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		client.Close()
		conn.Close()
		return nil, fmt.Errorf("failed to dial target through SSH: %w", err)
	}
	
	// Wrap connection for proper cleanup
	wrappedConn := &httpTunnelConn{
		Conn:   sshConn,
		ssh:    client,
		tunnel: conn,
		closer: s,
	}
	
	return NewConn(wrappedConn, s), nil
}

// httpTunnelConn wraps connections for proper cleanup
type httpTunnelConn struct {
	net.Conn
	ssh    *ssh.Client
	tunnel net.Conn
	closer *Ssh
}

func (c *httpTunnelConn) Close() error {
	var errs []error
	
	if c.ssh != nil {
		if err := c.ssh.Close(); err != nil {
			errs = append(errs, fmt.Errorf("ssh client close: %w", err))
		}
	}
	
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

// connect establishes direct SSH connection
func (s *Ssh) connect(ctx context.Context, addr string) (client *ssh.Client, err error) {
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	
	// Return existing client if available
	if s.client != nil {
		return s.client, nil
	}
	
	// Dial SSH server
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	
	c, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	// Setup context
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	// Establish SSH connection
	clientConn, chans, reqs, err := ssh.NewClientConn(c, addr, s.config)
	if err != nil {
		return nil, err
	}
	client = ssh.NewClient(clientConn, chans, reqs)
	s.client = client

	// Monitor connection and cleanup when closed
	go func() {
		_ = client.Wait()
		_ = client.Close()
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
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	
	var errs []error
	
	// Stop HTTP tunnel server if running
	if s.httpTunnelServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

// NewSsh creates a new SSH proxy instance
func NewSsh(option SshOption) (*Ssh, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	config := ssh.ClientConfig{
		User:              option.UserName,
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: option.HostKeyAlgorithms,
		Timeout:           15 * time.Second,
	}

	// Private key authentication
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

	// Password authentication
	if option.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(option.Password))
	}

	// Host key verification
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
		option: &option,
		config: &config,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}