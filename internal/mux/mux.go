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

	"github.com/hashicorp/yamux"
)

type Config struct {
	MaxFrameSize         int
	MaxReceiveBuffer     int
	MaxStreamBuffer      int
	KeepAliveInterval    time.Duration
	KeepAliveTimeout     time.Duration
	MaxConcurrentStreams int
}

// DefaultConfig — консервативные значения, чтобы один клиент не съедал
// всю пропускную способность сервера за счёт сотен голодных stream'ов.
//
// Раньше было: 4096 streams × 64MB stream buffer → один шумный клиент
// мог заголодать остальных и удерживать всю receive-window 256MB. После
// отжатых параметров max совокупная буферизация = 64 × 4MB = 256MB,
// то же самое глобально, но без HOL для медленных stream'ов через
// пропорциональное окно.
//
// Цифры подобраны для desktop/server. Если в проде нужен другой профиль
// (например, мобильный клиент с 64MB RAM) — пробрасывайте Config явно.
func DefaultConfig() *Config {
	return &Config{
		MaxFrameSize:         65536,
		MaxReceiveBuffer:     268435456, // 256 MB глобальный потолок (без изменений)
		MaxStreamBuffer:      16777216,  // 16 MB на stream
		KeepAliveInterval:    5 * time.Second,
		KeepAliveTimeout:     30 * time.Second,
		MaxConcurrentStreams: 64, // было 4096 — мультиплексирование без сюрпризов
	}
}

func (c *Config) toYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard

	if c.KeepAliveInterval > 0 {
		cfg.KeepAliveInterval = c.KeepAliveInterval
	}
	if c.KeepAliveTimeout > 0 {
		cfg.ConnectionWriteTimeout = c.KeepAliveTimeout
	}
	if c.MaxStreamBuffer > 0 {
		maxWin := uint32(c.MaxStreamBuffer)
		const yamuxMax = 256 * 1024 * 1024
		if maxWin > yamuxMax {
			maxWin = yamuxMax
		}
		cfg.MaxStreamWindowSize = maxWin
	}
	if c.MaxConcurrentStreams > 0 {
		cfg.AcceptBacklog = c.MaxConcurrentStreams
	}
	return cfg
}

type Session struct {
	streamsOpened uint64
	streamsClosed uint64
	bytesRx       uint64
	bytesTx       uint64

	session  *yamux.Session
	conn     net.Conn
	config   *Config
	mu       sync.RWMutex
	closed   int32
	isServer bool
}

func Client(conn net.Conn, cfg *Config) (*Session, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	session, err := yamux.Client(conn, cfg.toYamuxConfig())
	if err != nil {
		return nil, fmt.Errorf("yamux client create failed: %w", err)
	}

	return &Session{
		session:  session,
		conn:     conn,
		isServer: false,
		config:   cfg,
	}, nil
}

func Server(conn net.Conn, cfg *Config) (*Session, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	session, err := yamux.Server(conn, cfg.toYamuxConfig())
	if err != nil {
		return nil, fmt.Errorf("yamux server create failed: %w", err)
	}

	return &Session{
		session:  session,
		conn:     conn,
		isServer: true,
		config:   cfg,
	}, nil
}

func (s *Session) OpenStream() (net.Conn, error) {
	s.mu.RLock()
	if atomic.LoadInt32(&s.closed) == 1 {
		s.mu.RUnlock()
		return nil, errors.New("session closed")
	}
	s.mu.RUnlock()

	stream, err := s.session.Open()
	if err != nil {
		return nil, fmt.Errorf("open stream failed: %w", err)
	}

	atomic.AddUint64(&s.streamsOpened, 1)

	return &muxStream{
		Conn:    stream,
		session: s,
	}, nil
}

func (s *Session) OpenStreamContext(ctx context.Context) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		conn, err := s.OpenStream()
		select {
		case ch <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

func (s *Session) AcceptStream() (net.Conn, error) {
	s.mu.RLock()
	if atomic.LoadInt32(&s.closed) == 1 {
		s.mu.RUnlock()
		return nil, errors.New("session closed")
	}
	s.mu.RUnlock()

	stream, err := s.session.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept stream failed: %w", err)
	}

	atomic.AddUint64(&s.streamsOpened, 1)

	return &muxStream{
		Conn:    stream,
		session: s,
	}, nil
}

func (s *Session) AcceptStreamContext(ctx context.Context) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		conn, err := s.AcceptStream()
		select {
		case ch <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

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

func (s *Session) IsClosed() bool {
	if atomic.LoadInt32(&s.closed) == 1 {
		return true
	}
	return s.session.IsClosed()
}

func (s *Session) NumStreams() int {
	return s.session.NumStreams()
}

func (s *Session) Stats() (opened, closed, rx, tx uint64) {
	return atomic.LoadUint64(&s.streamsOpened),
		atomic.LoadUint64(&s.streamsClosed),
		atomic.LoadUint64(&s.bytesRx),
		atomic.LoadUint64(&s.bytesTx)
}

func (s *Session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

type muxStream struct {
	net.Conn
	session  *Session
	closed   int32
}

func (m *muxStream) Read(b []byte) (n int, err error) {
	n, err = m.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&m.session.bytesRx, uint64(n))
	}
	return
}

func (m *muxStream) Write(b []byte) (n int, err error) {
	n, err = m.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&m.session.bytesTx, uint64(n))
	}
	return
}

func (m *muxStream) Close() error {
	if atomic.CompareAndSwapInt32(&m.closed, 0, 1) {
		atomic.AddUint64(&m.session.streamsClosed, 1)
		return m.Conn.Close()
	}
	return nil
}

func (m *muxStream) LocalAddr() net.Addr {
	return m.session.LocalAddr()
}

func (m *muxStream) RemoteAddr() net.Addr {
	return m.session.RemoteAddr()
}

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

func DialWithConn(conn net.Conn, cfg *Config) (*Session, error) {
	return Client(conn, cfg)
}

func Listen(listener net.Listener, cfg *Config) *Listener {
	return &Listener{
		listener: listener,
		config:   cfg,
		sessions: make(chan *Session, 100),
	}
}

type Listener struct {
	listener net.Listener
	config   *Config
	sessions chan *Session
	closed   int32
	once     sync.Once
}

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

func (l *Listener) Close() error {
	if atomic.CompareAndSwapInt32(&l.closed, 0, 1) {
		close(l.sessions)
		return l.listener.Close()
	}
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}
