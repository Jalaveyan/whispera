// Package mux provides connection multiplexing using SMUX protocol
package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// Config holds multiplexer configuration
type Config struct {
	// MaxFrameSize is maximum size of a frame (default 4096)
	MaxFrameSize int
	// MaxReceiveBuffer is maximum buffer per stream
	MaxReceiveBuffer int
	// MaxStreamBuffer is maximum buffer per connection
	MaxStreamBuffer int
	// KeepAliveInterval is the interval for keep-alive packets
	KeepAliveInterval time.Duration
	// KeepAliveTimeout is timeout for keep-alive responses
	KeepAliveTimeout time.Duration
	// MaxConcurrentStreams is maximum streams per connection
	MaxConcurrentStreams int
}

// DefaultConfig returns default mux configuration
func DefaultConfig() *Config {
	return &Config{
		MaxFrameSize:         65536,              // Увеличено с 32768 для уменьшения overhead на фрагментацию
		MaxReceiveBuffer:     67108864,           // Увеличено с 4MB до 64MB для предотвращения потери пакетов
		MaxStreamBuffer:      16777216,           // Увеличено с 65536 до 16MB для лучшей буферизации потоков
		KeepAliveInterval:    10 * time.Second,
		KeepAliveTimeout:     30 * time.Second,
		MaxConcurrentStreams: 4096,               // Увеличено с 1024 для высоконагруженных сценариев
	}
}

// toSMUXConfig converts to smux.Config
func (c *Config) toSMUXConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	if c.MaxFrameSize > 0 {
		cfg.MaxFrameSize = c.MaxFrameSize
	}
	if c.MaxReceiveBuffer > 0 {
		cfg.MaxReceiveBuffer = c.MaxReceiveBuffer
	}
	if c.MaxStreamBuffer > 0 {
		cfg.MaxStreamBuffer = c.MaxStreamBuffer
	}
	if c.KeepAliveInterval > 0 {
		cfg.KeepAliveInterval = c.KeepAliveInterval
	}
	if c.KeepAliveTimeout > 0 {
		cfg.KeepAliveTimeout = c.KeepAliveTimeout
	}
	return cfg
}

// Session represents a multiplexed connection session
type Session struct {
	session  *smux.Session
	conn     net.Conn
	isServer bool
	config   *Config
	mu       sync.RWMutex

	// Stats
	streamsOpened uint64
	streamsClosed uint64
	bytesRx       uint64
	bytesTx       uint64
	closed        int32
}

// Client creates a client-side mux session over a connection
func Client(conn net.Conn, cfg *Config) (*Session, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	session, err := smux.Client(conn, cfg.toSMUXConfig())
	if err != nil {
		return nil, fmt.Errorf("smux client create failed: %w", err)
	}

	return &Session{
		session:  session,
		conn:     conn,
		isServer: false,
		config:   cfg,
	}, nil
}

// Server creates a server-side mux session over a connection
func Server(conn net.Conn, cfg *Config) (*Session, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	session, err := smux.Server(conn, cfg.toSMUXConfig())
	if err != nil {
		return nil, fmt.Errorf("smux server create failed: %w", err)
	}

	return &Session{
		session:  session,
		conn:     conn,
		isServer: true,
		config:   cfg,
	}, nil
}

// OpenStream opens a new stream (client-side)
func (s *Session) OpenStream() (net.Conn, error) {
	s.mu.RLock()
	if atomic.LoadInt32(&s.closed) == 1 {
		s.mu.RUnlock()
		return nil, errors.New("session closed")
	}
	s.mu.RUnlock()

	stream, err := s.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream failed: %w", err)
	}

	atomic.AddUint64(&s.streamsOpened, 1)

	return &muxStream{
		Stream:  stream,
		session: s,
	}, nil
}

// OpenStreamContext opens a stream with context support
func (s *Session) OpenStreamContext(ctx context.Context) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		conn, err := s.OpenStream()
		ch <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// AcceptStream accepts an incoming stream (server-side)
func (s *Session) AcceptStream() (net.Conn, error) {
	s.mu.RLock()
	if atomic.LoadInt32(&s.closed) == 1 {
		s.mu.RUnlock()
		return nil, errors.New("session closed")
	}
	s.mu.RUnlock()

	stream, err := s.session.AcceptStream()
	if err != nil {
		return nil, fmt.Errorf("accept stream failed: %w", err)
	}

	atomic.AddUint64(&s.streamsOpened, 1)

	return &muxStream{
		Stream:  stream,
		session: s,
	}, nil
}

// AcceptStreamContext accepts a stream with context support
func (s *Session) AcceptStreamContext(ctx context.Context) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		conn, err := s.AcceptStream()
		ch <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// Close closes the session and underlying connection
func (s *Session) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session != nil {
		s.session.Close()
	}
	if s.conn != nil {
		s.conn.Close()
	}

	return nil
}

// IsClosed returns true if session is closed
func (s *Session) IsClosed() bool {
	return atomic.LoadInt32(&s.closed) == 1 || s.session.IsClosed()
}

// NumStreams returns number of active streams
func (s *Session) NumStreams() int {
	return s.session.NumStreams()
}

// Stats returns session statistics
func (s *Session) Stats() (opened, closed, rx, tx uint64) {
	return atomic.LoadUint64(&s.streamsOpened),
		atomic.LoadUint64(&s.streamsClosed),
		atomic.LoadUint64(&s.bytesRx),
		atomic.LoadUint64(&s.bytesTx)
}

// LocalAddr returns local address of underlying connection
func (s *Session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns remote address of underlying connection
func (s *Session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// muxStream wraps smux.Stream to implement net.Conn and track stats
type muxStream struct {
	*smux.Stream
	session *Session
	closed  int32
}

func (m *muxStream) Read(b []byte) (n int, err error) {
	n, err = m.Stream.Read(b)
	if n > 0 {
		atomic.AddUint64(&m.session.bytesRx, uint64(n))
	}
	return
}

func (m *muxStream) Write(b []byte) (n int, err error) {
	n, err = m.Stream.Write(b)
	if n > 0 {
		atomic.AddUint64(&m.session.bytesTx, uint64(n))
	}
	return
}

func (m *muxStream) Close() error {
	if atomic.CompareAndSwapInt32(&m.closed, 0, 1) {
		atomic.AddUint64(&m.session.streamsClosed, 1)
		return m.Stream.Close()
	}
	return nil
}

func (m *muxStream) LocalAddr() net.Addr {
	return m.session.LocalAddr()
}

func (m *muxStream) RemoteAddr() net.Addr {
	return m.session.RemoteAddr()
}

// Dial creates a client mux session and opens a stream
func Dial(ctx context.Context, network, addr string, cfg *Config) (net.Conn, *Session, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, nil, err
	}

	session, err := Client(conn, cfg)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	stream, err := session.OpenStream()
	if err != nil {
		session.Close()
		return nil, nil, err
	}

	return stream, session, nil
}

// DialWithConn creates a client mux session over existing connection
func DialWithConn(conn net.Conn, cfg *Config) (*Session, error) {
	return Client(conn, cfg)
}

// Listen wraps a listener to accept mux sessions
func Listen(listener net.Listener, cfg *Config) *Listener {
	return &Listener{
		listener: listener,
		config:   cfg,
		sessions: make(chan *Session, 100),
	}
}

// Listener wraps a net.Listener for mux connections
type Listener struct {
	listener net.Listener
	config   *Config
	sessions chan *Session
	closed   int32
	once     sync.Once
}

// Accept accepts a new mux session
func (l *Listener) Accept() (*Session, error) {
	l.once.Do(func() {
		go l.acceptLoop()
	})

	session, ok := <-l.sessions
	if !ok {
		return nil, io.EOF
	}
	return session, nil
}

func (l *Listener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if atomic.LoadInt32(&l.closed) == 1 {
				return
			}
			continue
		}

		session, err := Server(conn, l.config)
		if err != nil {
			conn.Close()
			continue
		}

		select {
		case l.sessions <- session:
		default:
			session.Close()
		}
	}
}

// Close closes the listener
func (l *Listener) Close() error {
	if atomic.CompareAndSwapInt32(&l.closed, 0, 1) {
		close(l.sessions)
		return l.listener.Close()
	}
	return nil
}

// Addr returns the listener's address
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}
