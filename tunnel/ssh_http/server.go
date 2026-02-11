package ssh_http

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// Server implements a local HTTP CONNECT tunnel server for SSH-over-HTTP
type Server struct {
	config        *Config
	listener      net.Listener
	mu            sync.RWMutex
	running       bool
	localAddr     string
	connections   map[uint64]*Tunnel
	remoteAddrStr string
	shutdownChan  chan struct{}
	acceptChan    chan net.Conn
	acceptErrChan chan error
}

// Config contains HTTP tunnel server configuration
type Config struct {
	LocalAddress  string `yaml:"local-address,omitempty" json:"local_address,omitempty"`
	RemoteAddress string `yaml:"remote-address" json:"remote_address"`
	LocalPayload  string `yaml:"payload,omitempty" json:"local_payload,omitempty"`
	RemotePayload string `yaml:"remote-payload,omitempty" json:"remote_payload,omitempty"`
	BufferSize    uint64 `yaml:"buffer-size,omitempty" json:"buffer_size,omitempty"`
}

// NewServer creates a new HTTP tunnel server
func NewServer(config *Config) *Server {
	return &Server{
		config:        config,
		running:       false,
		connections:   make(map[uint64]*Tunnel),
		remoteAddrStr: config.RemoteAddress,
		shutdownChan:  make(chan struct{}),
		acceptChan:    make(chan net.Conn, 10),
		acceptErrChan: make(chan error, 1),
	}
}

// Start starts the HTTP tunnel server
func (s *Server) Start() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return s.localAddr, nil
	}

	// Use random available port if not specified
	if s.config.LocalAddress == "" {
		s.config.LocalAddress = "127.0.0.1:0"
	}

	// Resolve local address
	lAddr, err := net.ResolveTCPAddr("tcp", s.config.LocalAddress)
	if err != nil {
		return "", fmt.Errorf("failed to resolve local address: %w", err)
	}

	// Start listening
	listener, err := net.Listen("tcp", lAddr.String())
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
	}
	
	s.listener = listener
	s.localAddr = listener.Addr().String()
	s.running = true

	log.Infoln("[SSH-HTTP] Tunnel server started on %s -> %s", s.localAddr, s.remoteAddrStr)
	
	// Start accept loop
	go s.acceptLoop(lAddr)
	return s.localAddr, nil
}

// acceptLoop accepts incoming connections with cancellable accept
func (s *Server) acceptLoop(lAddr *net.TCPAddr) {
	var connId = uint64(0)
	
	// Goroutine untuk menerima koneksi
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case s.acceptErrChan <- err:
				default:
				}
				return
			}
			select {
			case s.acceptChan <- conn:
			case <-s.shutdownChan:
				conn.Close()
				return
			}
		}
	}()
	
	for {
		select {
		case <-s.shutdownChan:
			return
		case err := <-s.acceptErrChan:
			if errors.Is(err, net.ErrClosed) {
				log.Debugln("[SSH-HTTP] Listener closed")
				return
			}
			log.Errorln("[SSH-HTTP] Failed to accept connection: %s", err)
			// Continue listening for new connections
			go func() {
				conn, err := s.listener.Accept()
				if err != nil {
					select {
					case s.acceptErrChan <- err:
					default:
					}
					return
				}
				select {
				case s.acceptChan <- conn:
				case <-s.shutdownChan:
					conn.Close()
				}
			}()
			continue
		case conn := <-s.acceptChan:
			connId += 1
			s.handleConnection(connId, conn, lAddr)
		}
	}
}

// handleConnection handles a single accepted connection
func (s *Server) handleConnection(connId uint64, conn net.Conn, lAddr *net.TCPAddr) {
	// Create new tunnel for connection
	tunnel := NewTunnel(connId, conn, lAddr, s.remoteAddrStr)
	if s.config.BufferSize > 0 {
		tunnel.SetBufferSize(s.config.BufferSize)
	}
	tunnel.SetLocalPayload(s.config.LocalPayload)
	tunnel.SetRemotePayload(s.config.RemotePayload)
	
	// Store tunnel
	s.mu.Lock()
	s.connections[connId] = tunnel
	s.mu.Unlock()
	
	// Start tunnel in goroutine
	go func(t *Tunnel, id uint64) {
		defer func() {
			if r := recover(); r != nil {
				log.Errorln("[SSH-HTTP] Recovered from panic in tunnel #%d: %v", id, r)
			}
		}()
		
		t.Start()
		s.mu.Lock()
		delete(s.connections, id)
		s.mu.Unlock()
	}(tunnel, connId)
}

// Stop stops the server with graceful shutdown
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.running {
		return nil
	}
	
	s.running = false
	close(s.shutdownChan)
	
	// Close all active connections
	for id, tunnel := range s.connections {
		tunnel.Cancel()
		delete(s.connections, id)
	}
	
	// Close listener with timeout
	if s.listener != nil {
		errChan := make(chan error, 1)
		go func() {
			errChan <- s.listener.Close()
		}()
		
		select {
		case err := <-errChan:
			if err != nil {
				return fmt.Errorf("failed to close listener: %w", err)
			}
		case <-time.After(3 * time.Second):
			log.Warnln("[SSH-HTTP] Timeout closing listener")
		}
	}
	
	// Close channels
	close(s.acceptChan)
	close(s.acceptErrChan)
	
	log.Infoln("[SSH-HTTP] Tunnel server stopped")
	return nil
}

// GetLocalAddr returns the local address the server is listening on
func (s *Server) GetLocalAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localAddr
}

// IsRunning returns whether the server is running
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
