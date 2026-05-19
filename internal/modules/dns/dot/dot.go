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

	DefaultPort = 853

	maxDNSMessageSize = 65535
)

type Config struct {
	Servers []string

	TLSConfig *tls.Config

	ServerName string

	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	PoolSize     int
	MaxIdleConns int

	MaxRetries    int
	RetryInterval time.Duration

	FallbackToTCP bool

	ListenAddr string

	KeyLogFile string

	// DialContext routes DoT connections through a proxy/tunnel.
	// If nil, direct system dial is used (potential IP leak).
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

func DefaultConfig() *Config {
	return &Config{
		Servers: []string{
			"1.1.1.1:853",
			"8.8.8.8:853",
			"9.9.9.9:853",
			"77.88.8.8:853",
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

func (c *Config) Validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("at least one DoT server is required")
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	pools    map[string]*connPool
	listener net.Listener

	totalQueries   uint64
	successQueries uint64
	failedQueries  uint64
	cacheHits      uint64
	cacheMu sync.RWMutex
	cache   map[string]*dnsCacheEntry
}

type dnsCacheEntry struct {
	Response    []byte
	ExpiresAt   time.Time
	PrefetchAt  time.Time
	Prefetching atomic.Bool
}

type connPool struct {
	mu     sync.Mutex
	server string
	conns  chan *dotConn
	size   int
	config *Config

	creates  uint64
	reuses   uint64
	discards uint64
}

type dotConn struct {
	net.Conn
	tlsConn  *tls.Conn
	lastUsed time.Time
	inUse    atomic.Bool
}

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
		cache:  make(map[string]*dnsCacheEntry),
	}

	for _, server := range cfg.Servers {
		t.pools[server] = newConnPool(server, cfg)
	}

	return t, nil
}

func newConnPool(server string, cfg *Config) *connPool {
	return &connPool{
		server: server,
		conns:  make(chan *dotConn, cfg.PoolSize),
		size:   cfg.PoolSize,
		config: cfg,
	}
}

func (p *connPool) get(ctx context.Context) (*dotConn, error) {
	select {
	case conn := <-p.conns:
		if time.Since(conn.lastUsed) < p.config.IdleTimeout {
			atomic.AddUint64(&p.reuses, 1)
			return conn, nil
		}
		conn.Close()
		atomic.AddUint64(&p.discards, 1)
	default:
	}

	return p.dial(ctx)
}

func (p *connPool) put(conn *dotConn) {
	conn.lastUsed = time.Now()
	conn.inUse.Store(false)

	select {
	case p.conns <- conn:
	default:
		conn.Close()
		atomic.AddUint64(&p.discards, 1)
	}
}

func (p *connPool) dial(ctx context.Context) (*dotConn, error) {
	atomic.AddUint64(&p.creates, 1)

	tlsConfig := p.config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		}
	}

	if p.config.ServerName != "" {
		tlsConfig.ServerName = p.config.ServerName
	} else {
		host, _, _ := net.SplitHostPort(p.server)
		tlsConfig.ServerName = host
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.config.DialTimeout)
	defer cancel()

	var tlsConn *tls.Conn
	if p.config.DialContext != nil {
		rawConn, err := p.config.DialContext(dialCtx, "tcp", p.server)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s: %w", p.server, err)
		}
		c := tls.Client(rawConn, tlsConfig)
		if err := c.HandshakeContext(dialCtx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake failed for %s: %w", p.server, err)
		}
		tlsConn = c
	} else {
		dialer := &net.Dialer{Timeout: p.config.DialTimeout}
		c, err := (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(context.Background(), "tcp", p.server)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s: %w", p.server, err)
		}
		tlsConn = c.(*tls.Conn)
	}

	return &dotConn{
		Conn:     tlsConn,
		tlsConn:  tlsConn,
		lastUsed: time.Now(),
	}, nil
}

func (t *Transport) Query(ctx context.Context, msg []byte) ([]byte, error) {
	key := extractCacheKey(msg)
	if key != "" {
		t.cacheMu.RLock()
		entry, ok := t.cache[key]
		t.cacheMu.RUnlock()

		if ok {
			if time.Now().Before(entry.ExpiresAt) {
				atomic.AddUint64(&t.cacheHits, 1)

				if time.Now().After(entry.PrefetchAt) && entry.Prefetching.CompareAndSwap(false, true) {
					go func() {
						resp, err := t.executeNetworkQuery(context.Background(), msg)
						if err == nil {
							ttl := parseTTL(resp)
							t.cacheMu.Lock()
							t.cache[key] = &dnsCacheEntry{
								Response:   resp,
								ExpiresAt:  time.Now().Add(ttl),
								PrefetchAt: time.Now().Add(ttl * 3 / 4),
							}
							t.cacheMu.Unlock()
						}
						entry.Prefetching.Store(false)
					}()
				}
				resp := make([]byte, len(entry.Response))
				copy(resp, entry.Response)

				if len(resp) >= 2 && len(msg) >= 2 {
					resp[0], resp[1] = msg[0], msg[1]
				}
				return resp, nil
			} else {
				t.cacheMu.Lock()
				delete(t.cache, key)
				t.cacheMu.Unlock()
			}
		}
	}

	resp, err := t.executeNetworkQuery(ctx, msg)
	if err == nil && key != "" {
		ttl := parseTTL(resp)
		t.cacheMu.Lock()
		t.cache[key] = &dnsCacheEntry{
			Response:   resp,
			ExpiresAt:  time.Now().Add(ttl),
			PrefetchAt: time.Now().Add(ttl * 3 / 4),
		}
		t.cacheMu.Unlock()
	}
	return resp, err
}

func (t *Transport) executeNetworkQuery(ctx context.Context, msg []byte) ([]byte, error) {
	atomic.AddUint64(&t.totalQueries, 1)

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type result struct {
		response []byte
		err      error
	}

	resultCh := make(chan result, len(t.config.Servers))

	for _, server := range t.config.Servers {
		pool := t.pools[server]
		if pool == nil {
			continue
		}

		go func(p *connPool, srv string) {
			for retry := 0; retry <= t.config.MaxRetries; retry++ {
				select {
				case <-raceCtx.Done():
					return
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

	select {
	case res := <-resultCh:
		atomic.AddUint64(&t.successQueries, 1)
		return res.response, nil
	case <-ctx.Done():
		atomic.AddUint64(&t.failedQueries, 1)
		return nil, ctx.Err()
	case <-time.After(t.config.DialTimeout * time.Duration(t.config.MaxRetries+1)):
		atomic.AddUint64(&t.failedQueries, 1)
		if t.config.FallbackToTCP && len(t.config.Servers) > 0 {
			return t.queryTCP(t.config.Servers[0], msg)
		}
		return nil, fmt.Errorf("all DoT servers failed or timed out")
	}
}

func (t *Transport) queryServer(ctx context.Context, pool *connPool, msg []byte) ([]byte, error) {
	conn, err := pool.get(ctx)
	if err != nil {
		return nil, err
	}

	if t.config.WriteTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(t.config.WriteTimeout))
	}
	if t.config.ReadTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(t.config.ReadTimeout))
	}

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

	if _, err := io.ReadFull(conn, length); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(length)

	if respLen > maxDNSMessageSize {
		conn.Close()
		return nil, fmt.Errorf("response too large: %d", respLen)
	}

	response := make([]byte, respLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	pool.put(conn)

	return response, nil
}
func (t *Transport) queryTCP(server string, msg []byte) ([]byte, error) {
	host, port, _ := net.SplitHostPort(server)
	if port == "853" {
		port = "53"
	}
	tcpServer := net.JoinHostPort(host, port)

	conn, err := (&net.Dialer{Timeout: t.config.DialTimeout}).DialContext(context.Background(), "tcp", tcpServer)
	if err != nil {
		return nil, fmt.Errorf("TCP fallback failed: %w", err)
	}
	defer conn.Close()

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(msg)))
	if _, err := conn.Write(length); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

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

func (t *Transport) Listen(ctx context.Context) error {
	if t.config.ListenAddr == "" {
		return nil
	}

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

func (t *Transport) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		length := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(t.config.IdleTimeout))
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		queryLen := binary.BigEndian.Uint16(length)

		if queryLen > maxDNSMessageSize {
			return
		}

		query := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		response, err := t.Query(ctx, query)
		if err != nil {
			log.Debug("Query failed: %v", err)
			continue
		}

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
		"cache_hits":      atomic.LoadUint64(&t.cacheHits),
		"pools":           poolStats,
	}
}

func extractCacheKey(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	offset := 12
	if offset >= len(msg) {
		return ""
	}

	for offset < len(msg) {
		b := msg[offset]
		if b == 0 {
			offset++
			break
		}
		if (b & 0xC0) == 0xC0 {
			offset += 2
			break
		}
		offset += int(b) + 1
	}

	offset += 4

	if offset > len(msg) {
		return ""
	}

	return string(msg[12:offset])
}

func parseTTL(msg []byte) time.Duration {
	if len(msg) < 12 {
		return 0
	}

	qdCount := binary.BigEndian.Uint16(msg[4:6])
	anCount := binary.BigEndian.Uint16(msg[6:8])

	if anCount == 0 {
		return 30 * time.Second
	}

	offset := 12
	for i := 0; i < int(qdCount); i++ {
		if offset >= len(msg) {
			return 0
		}
		for offset < len(msg) {
			b := msg[offset]
			if b == 0 {
				offset++
				break
			}
			if (b & 0xC0) == 0xC0 {
				offset += 2
				break
			}
			offset += int(b) + 1
		}
		offset += 4
	}

	minTTL := uint32(3600)
	found := false

	for i := 0; i < int(anCount); i++ {
		if offset >= len(msg) {
			break
		}

		for offset < len(msg) {
			b := msg[offset]
			if b == 0 {
				offset++
				break
			}
			if (b & 0xC0) == 0xC0 {
				offset += 2
				break
			}
			offset += int(b) + 1
		}

		if offset+10 > len(msg) {
			break
		}

		ttl := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
		if ttl < minTTL {
			minTTL = ttl
		}
		found = true

		rdLen := binary.BigEndian.Uint16(msg[offset+8 : offset+10])
		offset += 10 + int(rdLen)
	}

	if !found {
		return 60 * time.Second
	}

	if minTTL < 10 {
		minTTL = 10
	}
	if minTTL > 3600 {
		minTTL = 3600
	}

	return time.Duration(minTTL) * time.Second
}
