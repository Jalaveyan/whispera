// Package dot implements DNS over TLS (DoT) transport
// RFC 7858 - Specification for DNS over Transport Layer Security (TLS)
package dot

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("dot")

const (
	ModuleName    = "dns.dot"
	ModuleVersion = "1.0.0"

	// Default DoT port
	DefaultPort = 853

	// Buffer sizes
	maxDNSMessageSize = 65535
)

// Config holds DoT configuration
type Config struct {
	// Upstream DoT servers
	Servers []string

	// TLS configuration
	TLSConfig *tls.Config

	// Server name for TLS verification
	ServerName string

	// Timeout settings
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Connection pool
	PoolSize     int
	MaxIdleConns int

	// Retry settings
	MaxRetries    int
	RetryInterval time.Duration

	// Fallback to TCP
	FallbackToTCP bool

	// Listen address for local DoT server
	ListenAddr string

	// SSLKEYLOGFILE for debugging
	KeyLogFile string
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Servers: []string{
			"1.1.1.1:853", // Cloudflare
			"8.8.8.8:853", // Google
			"9.9.9.9:853", // Quad9
		},
		DialTimeout:   5 * time.Second,
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  5 * time.Second,
		IdleTimeout:   60 * time.Second,
		PoolSize:      2,
		MaxIdleConns:  10,
		MaxRetries:    3,
		RetryInterval: 100 * time.Millisecond,
		FallbackToTCP: true,
	}
}

// Validate validates configuration
func (c *Config) Validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("at least one DoT server is required")
	}
	return nil
}

// Transport implements DoT transport
type Transport struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	pools    map[string]*connPool
	listener net.Listener

	// Stats
	totalQueries   uint64
	successQueries uint64
	failedQueries  uint64
	cacheHits      uint64
}

// connPool manages a pool of DoT connections
type connPool struct {
	mu     sync.Mutex
	server string
	conns  chan *dotConn
	size   int
	config *Config

	// Stats
	creates  uint64
	reuses   uint64
	discards uint64
}

// dotConn wraps a DoT connection
type dotConn struct {
	net.Conn
	tlsConn  *tls.Conn
	lastUsed time.Time
	inUse    atomic.Bool
}

// New creates a new DoT transport
func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		pools:  make(map[string]*connPool),
	}

	// Initialize connection pools
	for _, server := range cfg.Servers {
		t.pools[server] = newConnPool(server, cfg)
	}

	return t, nil
}

// newConnPool creates a new connection pool
func newConnPool(server string, cfg *Config) *connPool {
	return &connPool{
		server: server,
		conns:  make(chan *dotConn, cfg.PoolSize),
		size:   cfg.PoolSize,
		config: cfg,
	}
}

// get gets a connection from the pool
func (p *connPool) get(ctx context.Context) (*dotConn, error) {
	// Try to get an existing connection
	select {
	case conn := <-p.conns:
		if time.Since(conn.lastUsed) < p.config.IdleTimeout {
			atomic.AddUint64(&p.reuses, 1)
			return conn, nil
		}
		// Connection expired
		conn.Close()
		atomic.AddUint64(&p.discards, 1)
	default:
	}

	// Create new connection
	return p.dial(ctx)
}

// put returns a connection to the pool
func (p *connPool) put(conn *dotConn) {
	conn.lastUsed = time.Now()
	conn.inUse.Store(false)

	select {
	case p.conns <- conn:
	default:
		// Pool is full, close connection
		conn.Close()
		atomic.AddUint64(&p.discards, 1)
	}
}

// dial creates a new DoT connection
func (p *connPool) dial(_ context.Context) (*dotConn, error) {
	atomic.AddUint64(&p.creates, 1)

	// Create TLS config
	tlsConfig := p.config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	if p.config.ServerName != "" {
		tlsConfig.ServerName = p.config.ServerName
	} else {
		host, _, _ := net.SplitHostPort(p.server)
		tlsConfig.ServerName = host
	}

	// Dial with timeout
	dialer := &net.Dialer{
		Timeout: p.config.DialTimeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", p.server, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", p.server, err)
	}

	return &dotConn{
		Conn:     conn,
		tlsConn:  conn,
		lastUsed: time.Now(),
	}, nil
}

// Query sends a DNS query via DoT with parallel server racing
func (t *Transport) Query(ctx context.Context, msg []byte) ([]byte, error) {
	atomic.AddUint64(&t.totalQueries, 1)

	// Create a cancellable context for racing
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type result struct {
		response []byte
		err      error
	}

	// Channel for first successful result
	resultCh := make(chan result, len(t.config.Servers))

	// Launch parallel queries to all servers
	for _, server := range t.config.Servers {
		pool := t.pools[server]
		if pool == nil {
			continue
		}

		go func(p *connPool, srv string) {
			for retry := 0; retry <= t.config.MaxRetries; retry++ {
				select {
				case <-raceCtx.Done():
					return // Another server already responded
				default:
				}

				response, err := t.queryServer(raceCtx, p, msg)
				if err == nil {
					select {
					case resultCh <- result{response: response}:
					default:
					}
					return
				}

				if retry < t.config.MaxRetries {
					select {
					case <-raceCtx.Done():
						return
					case <-time.After(t.config.RetryInterval):
					}
				}
			}
		}(pool, server)
	}

	// Wait for first successful response or timeout
	select {
	case res := <-resultCh:
		atomic.AddUint64(&t.successQueries, 1)
		return res.response, nil
	case <-ctx.Done():
		atomic.AddUint64(&t.failedQueries, 1)
		return nil, ctx.Err()
	case <-time.After(t.config.DialTimeout * time.Duration(t.config.MaxRetries+1)):
		atomic.AddUint64(&t.failedQueries, 1)
		// Fallback to plain TCP if enabled
		if t.config.FallbackToTCP && len(t.config.Servers) > 0 {
			return t.queryTCP(t.config.Servers[0], msg)
		}
		return nil, fmt.Errorf("all DoT servers failed or timed out")
	}
}

// queryServer queries a single DoT server
func (t *Transport) queryServer(ctx context.Context, pool *connPool, msg []byte) ([]byte, error) {
	conn, err := pool.get(ctx)
	if err != nil {
		return nil, err
	}

	// Set deadlines
	if t.config.WriteTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(t.config.WriteTimeout))
	}
	if t.config.ReadTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(t.config.ReadTimeout))
	}

	// Send query with length prefix
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(msg)))

	if _, err := conn.Write(length); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write length: %w", err)
	}
	if _, err := conn.Write(msg); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write message: %w", err)
	}

	// Read response length
	if _, err := io.ReadFull(conn, length); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(length)

	if respLen > maxDNSMessageSize {
		conn.Close()
		return nil, fmt.Errorf("response too large: %d", respLen)
	}

	// Read response
	response := make([]byte, respLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Return connection to pool
	pool.put(conn)

	return response, nil
}

// queryTCP sends a DNS query via plain TCP
func (t *Transport) queryTCP(server string, msg []byte) ([]byte, error) {
	host, port, _ := net.SplitHostPort(server)
	if port == "853" {
		port = "53"
	}
	tcpServer := net.JoinHostPort(host, port)

	conn, err := net.DialTimeout("tcp", tcpServer, t.config.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("TCP fallback failed: %w", err)
	}
	defer conn.Close()

	// Send with length prefix
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(msg)))
	if _, err := conn.Write(length); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	// Read response
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(length)

	response := make([]byte, respLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}

	return response, nil
}

// Server functionality

// Listen starts the DoT server
func (t *Transport) Listen(ctx context.Context) error {
	if t.config.ListenAddr == "" {
		return nil
	}

	// Create TLS config for server
	tlsConfig := t.config.TLSConfig
	if tlsConfig == nil {
		return fmt.Errorf("TLS config required for DoT server")
	}

	listener, err := tls.Listen("tcp", t.config.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	t.mu.Lock()
	t.listener = listener
	t.mu.Unlock()

	log.Info("DoT server listening on %s", t.config.ListenAddr)

	go t.acceptLoop(ctx)

	return nil
}

// acceptLoop accepts incoming DoT connections
func (t *Transport) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := t.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("Accept error: %v", err)
			continue
		}

		go t.handleConnection(ctx, conn)
	}
}

// handleConnection handles a DoT client connection
func (t *Transport) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read query length
		length := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(t.config.IdleTimeout))
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		queryLen := binary.BigEndian.Uint16(length)

		if queryLen > maxDNSMessageSize {
			return
		}

		// Read query
		query := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		// Forward query upstream
		response, err := t.Query(ctx, query)
		if err != nil {
			log.Debug("Query failed: %v", err)
			continue
		}

		// Send response
		binary.BigEndian.PutUint16(length, uint16(len(response)))
		conn.SetWriteDeadline(time.Now().Add(t.config.WriteTimeout))
		if _, err := conn.Write(length); err != nil {
			return
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

// Transport interface implementation

func (t *Transport) Init(ctx context.Context) error {
	return nil
}

func (t *Transport) Start(ctx context.Context) error {
	return t.Listen(ctx)
}

func (t *Transport) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.listener != nil {
		t.listener.Close()
	}

	// Close all pool connections
	for _, pool := range t.pools {
		close(pool.conns)
		for conn := range pool.conns {
			conn.Close()
		}
	}

	return nil
}

func (t *Transport) Stats() map[string]interface{} {
	poolStats := make(map[string]interface{})
	for server, pool := range t.pools {
		poolStats[server] = map[string]interface{}{
			"creates":  atomic.LoadUint64(&pool.creates),
			"reuses":   atomic.LoadUint64(&pool.reuses),
			"discards": atomic.LoadUint64(&pool.discards),
		}
	}

	return map[string]interface{}{
		"total_queries":   atomic.LoadUint64(&t.totalQueries),
		"success_queries": atomic.LoadUint64(&t.successQueries),
		"failed_queries":  atomic.LoadUint64(&t.failedQueries),
		"pools":           poolStats,
	}
}
