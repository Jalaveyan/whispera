// Package grpc provides gRPC transport module implementation
package grpc

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "transport.grpc"
	ModuleVersion = "1.0.0"
)

// Config holds gRPC transport configuration
type Config struct {
	ListenAddr  string
	ServiceName string
	UseTLS      bool
	CertFile    string
	KeyFile     string
	ServerName  string // For client SNI
	MaxConns    int
	MaxStreams  int
}

// DefaultConfig returns default gRPC configuration
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:  ":8443",
		ServiceName: "TunnelService",
		UseTLS:      true,
		MaxConns:    10000,
		MaxStreams:  100,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.ServiceName == "" {
		c.ServiceName = "TunnelService"
	}
	return nil
}

// Transport implements interfaces.Transport for gRPC
type Transport struct {
	*base.Module
	config     *Config
	server     *grpc.Server
	mu         sync.RWMutex
	acceptChan chan net.Conn

	// Stats
	connCount   int64
	bytesRx     uint64
	bytesTx     uint64
	activeConns int64
}

// New creates a new gRPC transport module
func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		acceptChan: make(chan net.Conn, 1000),
	}

	return t, nil
}

// Init initializes the transport
func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if grpcCfg, ok := cfg.(*Config); ok {
		t.config = grpcCfg
	}

	return nil
}

// Start starts the gRPC transport
func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	// Create gRPC server options
	var opts []grpc.ServerOption

	if t.config.UseTLS && t.config.CertFile != "" && t.config.KeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(t.config.CertFile, t.config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	opts = append(opts, grpc.MaxConcurrentStreams(uint32(t.config.MaxStreams)))

	t.server = grpc.NewServer(opts...)

	// Register tunnel service
	RegisterTunnelServiceServer(t.server, &tunnelServer{transport: t})

	// Start listener
	listener, err := net.Listen("tcp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		if err := t.server.Serve(listener); err != nil {
			t.SetHealthy(false, fmt.Sprintf("server error: %v", err))
		}
	}()

	t.SetHealthy(true, fmt.Sprintf("listening on %s", t.config.ListenAddr))
	t.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr":  t.config.ListenAddr,
		"service_name": t.config.ServiceName,
	})

	return nil
}

// Stop stops the gRPC transport
func (t *Transport) Stop() error {
	t.mu.Lock()
	if t.server != nil {
		t.server.GracefulStop()
		t.server = nil
	}
	t.mu.Unlock()

	close(t.acceptChan)

	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

// Type returns the transport type
func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportType("grpc")
}

// Listen is a no-op (listening started in Start)
func (t *Transport) Listen(addr string) error {
	return nil
}

// Dial connects to a remote gRPC server
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	var opts []grpc.DialOption

	if t.config.UseTLS {
		creds := credentials.NewClientTLSFromCert(nil, t.config.ServerName)
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.DialContext(ctx, addr, opts...)
	if err != nil {
		return nil, err
	}

	client := NewTunnelServiceClient(conn)

	// Create bidirectional stream
	stream, err := client.Tunnel(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}

	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)

	return &grpcConn{
		stream:    stream,
		transport: t,
		grpcConn:  conn,
	}, nil
}

// Accept accepts a new connection
func (t *Transport) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptChan
	if !ok {
		return nil, fmt.Errorf("transport stopped")
	}
	return conn, nil
}

// Close closes the transport
func (t *Transport) Close() error {
	return t.Stop()
}

// HealthCheck returns detailed health status
func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()
	status.Details["conn_count"] = atomic.LoadInt64(&t.connCount)
	status.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	status.Details["bytes_rx"] = atomic.LoadUint64(&t.bytesRx)
	status.Details["bytes_tx"] = atomic.LoadUint64(&t.bytesTx)
	return status
}

// ============ gRPC Service Definition ============

// TunnelServiceServer is the server interface (generated stub)
type TunnelServiceServer interface {
	Tunnel(TunnelService_TunnelServer) error
}

// TunnelServiceClient is the client interface
type TunnelServiceClient interface {
	Tunnel(ctx context.Context, opts ...grpc.CallOption) (TunnelService_TunnelClient, error)
}

// TunnelService_TunnelServer is the server stream interface
type TunnelService_TunnelServer interface {
	Send(*TunnelData) error
	Recv() (*TunnelData, error)
	grpc.ServerStream
}

// TunnelService_TunnelClient is the client stream interface
type TunnelService_TunnelClient interface {
	Send(*TunnelData) error
	Recv() (*TunnelData, error)
	grpc.ClientStream
}

// TunnelData is the data frame
type TunnelData struct {
	Data []byte
}

// RegisterTunnelServiceServer registers the tunnel service
func RegisterTunnelServiceServer(s *grpc.Server, srv TunnelServiceServer) {
	s.RegisterService(&_TunnelService_serviceDesc, srv)
}

// NewTunnelServiceClient creates a new client
func NewTunnelServiceClient(cc grpc.ClientConnInterface) TunnelServiceClient {
	return &tunnelServiceClient{cc}
}

type tunnelServiceClient struct {
	cc grpc.ClientConnInterface
}

func (c *tunnelServiceClient) Tunnel(ctx context.Context, opts ...grpc.CallOption) (TunnelService_TunnelClient, error) {
	stream, err := c.cc.NewStream(ctx, &_TunnelService_serviceDesc.Streams[0], "/tunnel.TunnelService/Tunnel", opts...)
	if err != nil {
		return nil, err
	}
	return &tunnelServiceTunnelClient{stream}, nil
}

type tunnelServiceTunnelClient struct {
	grpc.ClientStream
}

func (x *tunnelServiceTunnelClient) Send(m *TunnelData) error {
	return x.ClientStream.SendMsg(m)
}

func (x *tunnelServiceTunnelClient) Recv() (*TunnelData, error) {
	m := new(TunnelData)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _TunnelService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "tunnel.TunnelService",
	HandlerType: (*TunnelServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Tunnel",
			Handler:       _TunnelService_Tunnel_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "tunnel.proto",
}

func _TunnelService_Tunnel_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TunnelServiceServer).Tunnel(&tunnelServiceTunnelServer{stream})
}

type tunnelServiceTunnelServer struct {
	grpc.ServerStream
}

func (x *tunnelServiceTunnelServer) Send(m *TunnelData) error {
	return x.ServerStream.SendMsg(m)
}

func (x *tunnelServiceTunnelServer) Recv() (*TunnelData, error) {
	m := new(TunnelData)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// tunnelServer implements TunnelServiceServer
type tunnelServer struct {
	transport *Transport
	UnimplementedTunnelServiceServer
}

// UnimplementedTunnelServiceServer is for forward compatibility
type UnimplementedTunnelServiceServer struct{}

func (UnimplementedTunnelServiceServer) Tunnel(TunnelService_TunnelServer) error {
	return fmt.Errorf("Tunnel not implemented")
}

func (s *tunnelServer) Tunnel(stream TunnelService_TunnelServer) error {
	atomic.AddInt64(&s.transport.connCount, 1)
	atomic.AddInt64(&s.transport.activeConns, 1)

	conn := &grpcServerConn{
		stream:    stream,
		transport: s.transport,
	}

	// Send to accept channel
	select {
	case s.transport.acceptChan <- conn:
	default:
		atomic.AddInt64(&s.transport.activeConns, -1)
		return fmt.Errorf("accept channel full")
	}

	// Block until connection is closed
	<-conn.closeChan
	return nil
}

// grpcConn wraps a gRPC client stream as net.Conn
type grpcConn struct {
	stream    TunnelService_TunnelClient
	transport *Transport
	grpcConn  *grpc.ClientConn
	readBuf   []byte
	closed    int32
	mu        sync.Mutex
}

func (c *grpcConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return buffered data first
	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
		return n, nil
	}

	// Receive new data
	data, err := c.stream.Recv()
	if err != nil {
		return 0, err
	}

	n = copy(b, data.Data)
	if n < len(data.Data) {
		c.readBuf = data.Data[n:]
	}
	atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	return n, nil
}

func (c *grpcConn) Write(b []byte) (n int, err error) {
	err = c.stream.Send(&TunnelData{Data: b})
	if err != nil {
		return 0, err
	}
	atomic.AddUint64(&c.transport.bytesTx, uint64(len(b)))
	return len(b), nil
}

func (c *grpcConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		atomic.AddInt64(&c.transport.activeConns, -1)
		c.grpcConn.Close()
	}
	return nil
}

func (c *grpcConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *grpcConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *grpcConn) SetDeadline(t time.Time) error      { return nil }
func (c *grpcConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *grpcConn) SetWriteDeadline(t time.Time) error { return nil }

// grpcServerConn wraps a gRPC server stream as net.Conn
type grpcServerConn struct {
	stream    TunnelService_TunnelServer
	transport *Transport
	readBuf   []byte
	closed    int32
	closeChan chan struct{}
	mu        sync.Mutex
}

func (c *grpcServerConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
		return n, nil
	}

	data, err := c.stream.Recv()
	if err != nil {
		return 0, err
	}

	n = copy(b, data.Data)
	if n < len(data.Data) {
		c.readBuf = data.Data[n:]
	}
	atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	return n, nil
}

func (c *grpcServerConn) Write(b []byte) (n int, err error) {
	err = c.stream.Send(&TunnelData{Data: b})
	if err != nil {
		return 0, err
	}
	atomic.AddUint64(&c.transport.bytesTx, uint64(len(b)))
	return len(b), nil
}

func (c *grpcServerConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		atomic.AddInt64(&c.transport.activeConns, -1)
		if c.closeChan != nil {
			close(c.closeChan)
		}
	}
	return nil
}

func (c *grpcServerConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *grpcServerConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *grpcServerConn) SetDeadline(t time.Time) error      { return nil }
func (c *grpcServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *grpcServerConn) SetWriteDeadline(t time.Time) error { return nil }

// Factory creates gRPC transport modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}

// Ensure we implement the interface
var _ = (metadata.MD)(nil) // use metadata import
var _ = (io.Reader)(nil)   // use io import
