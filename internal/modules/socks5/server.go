package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"
	"whispera/internal/modules/relay"
	"whispera/internal/proxy"
)

const (
	ModuleName    = "socks5.server"
	ModuleVersion = "1.0.0"
)

// TunnelRelay interface for tunnel communication with frame support
type TunnelRelay interface {
	Send(data []byte) error
	Receive(buf []byte) (int, error)
	IsConnected() bool
}

// Config holds module configuration
type Config struct {
	ListenAddr string
	Username   string
	Password   string
	Debug      bool
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: "127.0.0.1:10800",
		Debug:      true,
	}
}

// Validate implements interfaces.ModuleConfig
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:10800"
	}
	return nil
}

// pendingConn represents a pending connection waiting for CONNECT_OK
type pendingConn struct {
	conn   net.Conn
	target string
	ready  chan error
	ctx    context.Context
	cancel context.CancelFunc
}

// Server implements the SOCKS5 server module
type Server struct {
	*base.Module
	config *Config

	// SOCKS5 Server
	server   *proxy.SOCKS5Server
	listener net.Listener

	// Dependencies
	tunnel TunnelRelay

	// Stream management (client-side)
	streamIDGen   *relay.StreamIDGenerator
	pendingConns  map[uint16]*pendingConn // streamID -> pending connection
	activeStreams map[uint16]net.Conn     // streamID -> active SOCKS5 client conn
	streamMu      sync.RWMutex

	// Stats
	connectSuccess uint64
	connectFailed  uint64
	bytesRelayed   uint64

	// Process
	cmd *exec.Cmd

	mu sync.RWMutex
}

// New creates a new SOCKS5 server module
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	s := &Server{
		Module:        base.NewModule(ModuleName, ModuleVersion, []string{"tunnel.manager"}),
		config:        cfg,
		streamIDGen:   relay.NewStreamIDGenerator(),
		pendingConns:  make(map[uint16]*pendingConn),
		activeStreams: make(map[uint16]net.Conn),
	}

	return s, nil
}

// Init initializes the module
func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if socketCfg, ok := cfg.(*Config); ok {
		s.config = socketCfg
	}

	return nil
}

// Start starts the SOCKS5 server
func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	// Initialize SOCKS5 server logic
	s.server = proxy.NewSOCKS5Server(s.config.ListenAddr, s.handleProxyRequest)

	// Optional Auth
	if s.config.Username != "" && s.config.Password != "" {
		s.server.SetAuthHandler(func(u, p string) bool {
			return u == s.config.Username && p == s.config.Password
		})
	}

	// Start listening
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			s.SetHealthy(false, fmt.Sprintf("Server error: %v", err))
		}
	}()

	// Start frame receiver
	go s.receiveFrames()

	// NOTE: HevTunnel is NOT started automatically
	// It should be started AFTER the VPN tunnel successfully connects
	// to avoid routing loops. Call StartHevTunnel() explicitly when ready.
	// if err := s.startHevTunnel(); err != nil {
	// 	s.SetHealthy(false, fmt.Sprintf("Failed to start HevTunnel: %v", err))
	// 	fmt.Printf("[SOCKS5] WARNING: Failed to start HevTunnel: %v\n", err)
	// }

	s.SetHealthy(true, fmt.Sprintf("Listening on %s", s.config.ListenAddr))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"addr": s.config.ListenAddr,
	})

	return nil
}

// Stop stops the module
func (s *Server) Stop() error {
	s.stopHevTunnel()

	// Close all pending connections
	s.streamMu.Lock()
	for _, pc := range s.pendingConns {
		pc.cancel()
	}
	for _, conn := range s.activeStreams {
		conn.Close()
	}
	s.pendingConns = make(map[uint16]*pendingConn)
	s.activeStreams = make(map[uint16]net.Conn)
	s.streamMu.Unlock()

	// Clean stop
	s.StopHevTunnel()
	s.PublishEvent(events.EventTypeModuleStopped, nil)
	return s.Module.Stop()
}

// StopHevTunnel forcibly kills the hev-socks5-tunnel process
func (s *Server) StopHevTunnel() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil && s.cmd.Process != nil {
		logger.Info("Stopping HevTunnel (PID: %d)", s.cmd.Process.Pid)
		// Try graceful kill first if supported
		s.cmd.Process.Kill()
	}

	s.cmd = nil

	// Force kill by image name as requested by user ("taskkill /F /IM hev-socks5-tunnel.exe")
	// This ensures checks for any dangling instances
	exec.Command("taskkill", "/F", "/IM", "hev-socks5-tunnel.exe").Run()
}

// SetTunnel sets the tunnel manager for encrypted traffic relay
func (s *Server) SetTunnel(t TunnelRelay) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnel = t
}

// StartHevTunnel starts the hev-socks5-tunnel TUN interface.
// This should be called AFTER the VPN tunnel is successfully connected
// to avoid routing loops.
func (s *Server) StartHevTunnel() error {
	return s.startHevTunnel()
}

func (s *Server) startHevTunnel() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil && s.cmd.Process != nil {
		return nil // Already running
	}

	// Locate binary - check multiple paths for Tauri/standalone
	cwd, _ := os.Getwd()
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)

	searchPaths := []string{
		// Tauri bundled resources
		filepath.Join(execDir, "core", "hev-socks5-tunnel", "hev-socks5-tunnel.exe"),
		filepath.Join(execDir, "resources", "core", "hev-socks5-tunnel", "hev-socks5-tunnel.exe"),
		// Development paths
		filepath.Join(cwd, "core", "hev-socks5-tunnel", "hev-socks5-tunnel.exe"),
		filepath.Join(cwd, "src-tauri", "core", "hev-socks5-tunnel", "hev-socks5-tunnel.exe"),
		// Bin directory (Tauri sidecar location)
		filepath.Join(execDir, "bin", "hev-socks5-tunnel.exe"),
		filepath.Join(cwd, "src-tauri", "bin", "hev-socks5-tunnel.exe"),
		// Fallback flat structure
		filepath.Join(cwd, "core", "hev-socks5-tunnel.exe"),
		filepath.Join(execDir, "hev-socks5-tunnel.exe"),
	}

	var binPath string
	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			binPath = path
			break
		}
	}

	if binPath == "" {
		return fmt.Errorf("hev-socks5-tunnel.exe not found in any of the search paths")
	}

	// Generate config.yml for hev-socks5-tunnel
	// Enable pipeline mode again as it provided stability
	hevLogPath := filepath.Join(os.TempDir(), "whispera-hev.log")
	// Make sure path uses forward slashes for cross-platform compatibility in yaml if needed, though Go handles it.
	// Actually for config file content on Windows backslashes are fine but need escaping.
	// Simplest is to just use the filename and let it write to CWD (which is set to bin dir),
	// OR use absolute path with double backslashes.
	// Let's rely on standard path but escaping check.
	hevLogPathEscaped := strings.ReplaceAll(hevLogPath, "\\", "\\\\")

	configContent := fmt.Sprintf(`tunnel:
  name: "Whispera"
  ipv4: "10.0.85.1"
  ipv6: "fd00::1"
  mtu: 1400

socks5:
  port: %d
  address: "%s"
  udp: "udp"
  tcp: "tcp"
  pipeline: false

misc:
  log-file: "%s"
  log-level: "debug"
  limit-nofile: 65535
  connect-timeout: 10000
`, getPort(s.config.ListenAddr), getHost(s.config.ListenAddr), hevLogPathEscaped)

	configPath := filepath.Join(os.TempDir(), "whispera-hev-config.yml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write hev config: %w", err)
	}

	// Start Process
	cmd := exec.Command(binPath, configPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = filepath.Dir(binPath)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start hev-socks5-tunnel: %w", err)
	}

	s.cmd = cmd
	fmt.Printf("[SOCKS5] HevTunnel started (PID: %d) from %s\n", cmd.Process.Pid, binPath)

	// Wait for TUN interface to be ready
	time.Sleep(2 * time.Second)

	// Check if process is still running
	if s.cmd.ProcessState != nil && s.cmd.ProcessState.Exited() {
		return fmt.Errorf("hev-socks5-tunnel exited unexpectedly")
	}

	// Configure routes
	s.configureRoutes()

	return nil
}

// configureRoutes sets up routing to send traffic through the TUN interface
// while excluding the VPN server IP to prevent routing loops
func (s *Server) configureRoutes() {
	logger.Info("Configuring routes...")

	// Get the VPN server IP from tunnel
	s.mu.RLock()
	tunnel := s.tunnel
	s.mu.RUnlock()

	var vpnServerIP string
	if tunnel != nil {
		// Try to get server address from tunnel config
		vpnServerIP = os.Getenv("WHISPERA_VPN_SERVER")
	}

	// 1. Auto-detect Default Gateway
	defaultGateway := s.getDefaultGateway()
	if defaultGateway == "" {
		logger.Error("Could not detect default gateway! Routing functionality may be limited.")
	} else {
		logger.Info("Auto-detected Default Gateway: %s", defaultGateway)
	}

	// TUN interface settings
	tunName := "Whispera"
	tunIP := "10.0.85.1"

	// 2. Add route for VPN server through Physical Gateway
	// route add <VPN_IP> mask 255.255.255.255 <GATEWAY> metric 1
	if vpnServerIP != "" && defaultGateway != "" {
		logger.Info("Adding route for VPN server %s via gateway %s", vpnServerIP, defaultGateway)
		// Delete potential existing route first
		exec.Command("route", "delete", vpnServerIP).Run()

		cmd := exec.Command("route", "add", vpnServerIP, "mask", "255.255.255.255", defaultGateway, "metric", "1")
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Error("Failed to add VPN route: %v %s", err, string(out))
		}
	} else {
		logger.Warn("Skipping VPN server route (missing VPN IP or Gateway)")
	}

	// 3. Force Interface Metric for Whispera to 1
	exec.Command("netsh", "interface", "ip", "set", "interface", tunName, "metric=1").Run()

	// 4. Determine TUN Interface Index
	tunIndex, _, err := getTunInterface(tunIP)
	if err != nil {
		logger.Warn("Failed to find TUN interface index: %v", err)
	} else {
		logger.Info("Detected TUN Interface Index: %d", tunIndex)
	}

	// 5. Add TUN Routes (hijack all traffic)
	// route add 0.0.0.0 mask 128.0.0.0 10.0.85.1 metric 1
	// route add 128.0.0.0 mask 128.0.0.0 10.0.85.1 metric 1
	logger.Info("Adding TUN routes...")

	var routeArgs [][]string
	if tunIndex > 0 {
		// Use IF index if available (more reliable)
		routeArgs = [][]string{
			{"route", "add", "0.0.0.0", "mask", "128.0.0.0", tunIP, "metric", "1", "if", fmt.Sprintf("%d", tunIndex)},
			{"route", "add", "128.0.0.0", "mask", "128.0.0.0", tunIP, "metric", "1", "if", fmt.Sprintf("%d", tunIndex)},
		}
	} else {
		routeArgs = [][]string{
			{"route", "add", "0.0.0.0", "mask", "128.0.0.0", tunIP, "metric", "1"},
			{"route", "add", "128.0.0.0", "mask", "128.0.0.0", tunIP, "metric", "1"},
		}
	}

	for _, args := range routeArgs {
		// Cleanup old
		exec.Command("route", "delete", args[2]).Run()

		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Error("Failed to add TUN route %s: %v %s", args[2], err, string(out))
		} else {
			logger.Info("Added TUN route: %s", strings.Join(args, " "))
		}
	}

	// IPv6 Leak Protection (Minimal)
	if tunIndex > 0 {
		exec.Command("netsh", "interface", "ipv6", "add", "route", "::/1", "interface="+fmt.Sprintf("%d", tunIndex), "metric=1").Run()
		exec.Command("netsh", "interface", "ipv6", "add", "route", "8000::/1", "interface="+fmt.Sprintf("%d", tunIndex), "metric=1").Run()
	}

	logger.Info("Smart routing configuration complete")
}

// getDefaultGateway attempts to detect the default gateway IP using 'route print'
func (s *Server) getDefaultGateway() string {
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// Standard line looks like:
		// 0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.15     25
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gateway := fields[2]
			// Check if it's a valid IP and not "On-link" (which sometimes happens)
			if net.ParseIP(gateway) != nil {
				return gateway
			}
		}
	}
	return ""
}

// getTunInterface finds the interface index and name by its assigned IP address
func getTunInterface(ip string) (int, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, "", err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// Check if IP matches
			if strings.Contains(addr.String(), ip) {
				return iface.Index, iface.Name, nil
			}
		}
	}
	return 0, "", fmt.Errorf("interface with IP %s not found", ip)
}

// getDefaultGateway tries to detect the default gateway on Windows
func getDefaultGateway() string {
	// Use route print 0.0.0.0 to find the active default gateway
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Output format example:
	// Network Destination        Netmask          Gateway       Interface  Metric
	//           0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			// Check if Gateway is a valid IP (not "On-link")
			gw := fields[2]
			if net.ParseIP(gw) != nil {
				return gw
			}
		}
	}

	return ""
}

// getHost extracts host from address
func getHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1"
	}
	return host
}

// getPort extracts port from address
func getPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 10800
	}
	port := 10800
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

func (s *Server) stopHevTunnel() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd = nil
	}
}

// handleProxyRequest is the callback from the SOCKS5 server when a connection is made
func (s *Server) handleProxyRequest(conn net.Conn, targetAddr string, targetPort uint16) error {
	// Filter traffic that should NOT go through VPN tunnel
	// This prevents multicast/local traffic from creating suspicious patterns
	if s.shouldBypassTunnel(targetAddr, targetPort) {
		if s.config.Debug {
			fmt.Printf("[SOCKS5] Bypassing tunnel for: %s:%d\n", targetAddr, targetPort)
		}
		return s.directConnect(conn, fmt.Sprintf("%s:%d", targetAddr, targetPort))
	}

	// Use relayThroughTunnel to send traffic through the encrypted VPN tunnel
	// The routing loop is prevented by the specific route for the VPN server IP
	return s.relayThroughTunnel(conn, targetAddr, targetPort)
}

// shouldBypassTunnel returns true if traffic should NOT go through VPN
func (s *Server) shouldBypassTunnel(addr string, port uint16) bool {
	// Skip mDNS (port 5353)
	if port == 5353 {
		return true
	}

	// Parse IP address
	ip := net.ParseIP(addr)
	if ip == nil {
		return false // Domain names go through tunnel
	}

	// Skip multicast (224.0.0.0/4)
	if ip[0] >= 224 && ip[0] <= 239 {
		return true
	}

	// Skip broadcast
	if ip.Equal(net.IPv4bcast) {
		return true
	}

	// Skip loopback
	if ip.IsLoopback() {
		return true
	}

	// Skip link-local (169.254.0.0/16)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Skip private networks (RFC 1918)
	// 10.0.0.0/8
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}

	return false
}

// relayThroughTunnel sends traffic through the encrypted VPN tunnel using relay protocol
func (s *Server) relayThroughTunnel(conn net.Conn, targetAddr string, targetPort uint16) error {
	// Generate stream ID
	streamID := s.streamIDGen.Next()

	// Determine address type
	var addrType uint8
	ip := net.ParseIP(targetAddr)
	if ip != nil {
		if ip.To4() != nil {
			addrType = relay.AddrTypeIPv4
		} else {
			addrType = relay.AddrTypeIPv6
		}
	} else {
		addrType = relay.AddrTypeDomain
	}

	// Create CONNECT frame
	frame := relay.NewConnectFrame(streamID, relay.ProtoTCP, addrType, targetAddr, targetPort, relay.ProfileBalanced)
	frameData, err := frame.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode frame: %w", err)
	}

	// Register pending connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pc := &pendingConn{
		conn:   conn,
		target: fmt.Sprintf("%s:%d", targetAddr, targetPort),
		ready:  make(chan error, 1),
		ctx:    ctx,
		cancel: cancel,
	}

	s.streamMu.Lock()
	s.pendingConns[streamID] = pc
	s.streamMu.Unlock()

	defer func() {
		s.streamMu.Lock()
		delete(s.pendingConns, streamID)
		s.streamMu.Unlock()
		cancel()
	}()

	// Send CONNECT frame
	if err := s.tunnel.Send(frameData); err != nil {
		atomic.AddUint64(&s.connectFailed, 1)
		if s.config.Debug {
			fmt.Printf("[SOCKS5] ERROR: Failed to send CONNECT frame: %v\n", err)
		}
		return fmt.Errorf("failed to send CONNECT frame: %w", err)
	}

	if s.config.Debug {
		fmt.Printf("[SOCKS5] Sent CONNECT frame streamID=%d to %s:%d\n", streamID, targetAddr, targetPort)
	}

	// Wait for CONNECT_OK or CONNECT_FAIL
	select {
	case err := <-pc.ready:
		if err != nil {
			atomic.AddUint64(&s.connectFailed, 1)
			return err
		}
	case <-ctx.Done():
		atomic.AddUint64(&s.connectFailed, 1)
		return fmt.Errorf("connection timeout")
	}

	atomic.AddUint64(&s.connectSuccess, 1)

	if s.config.Debug {
		fmt.Printf("[SOCKS5] Connection established streamID=%d\n", streamID)
	}

	// Register active stream
	s.streamMu.Lock()
	s.activeStreams[streamID] = conn
	s.streamMu.Unlock()

	defer func() {
		s.streamMu.Lock()
		delete(s.activeStreams, streamID)
		s.streamMu.Unlock()

		// Send CLOSE frame
		closeFrame := relay.NewCloseFrame(streamID)
		if data, err := closeFrame.Encode(); err == nil {
			s.tunnel.Send(data)
		}
	}()

	// Start bidirectional relay
	var wg sync.WaitGroup
	wg.Add(1)

	// Client -> Tunnel (send DATA frames)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}

			// Create DATA frame
			dataFrame := relay.NewDataFrame(streamID, buf[:n])
			frameData, err := dataFrame.Encode()
			if err != nil {
				return
			}

			if err := s.tunnel.Send(frameData); err != nil {
				return
			}

			atomic.AddUint64(&s.bytesRelayed, uint64(n))
		}
	}()

	// Tunnel -> Client is handled by receiveFrames goroutine

	wg.Wait()
	return nil
}

// receiveFrames continuously receives frames from the tunnel and dispatches them
func (s *Server) receiveFrames() {
	buf := make([]byte, 65535+relay.HeaderSize)

	for s.IsRunning() {
		s.mu.RLock()
		tunnel := s.tunnel
		s.mu.RUnlock()

		if tunnel == nil || !tunnel.IsConnected() {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n, err := tunnel.Receive(buf)
		if err != nil {
			if err != io.EOF {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}

		if n < relay.HeaderSize {
			continue
		}

		// Decode frame
		frame, err := relay.Decode(buf[:n])
		if err != nil {
			if s.config.Debug {
				fmt.Printf("[SOCKS5] Failed to decode frame: %v\n", err)
			}
			continue
		}

		// Handle frame
		s.handleIncomingFrame(frame)
	}
}

// handleIncomingFrame processes frames received from the tunnel
func (s *Server) handleIncomingFrame(frame *relay.Frame) {
	switch frame.Type {
	case relay.FrameConnectOK:
		s.handleConnectOK(frame)
	case relay.FrameConnectFail:
		s.handleConnectFail(frame)
	case relay.FrameData:
		s.handleData(frame)
	case relay.FrameClose:
		s.handleClose(frame)
	case relay.FramePong:
		// Keep-alive response, ignore
	default:
		if s.config.Debug {
			fmt.Printf("[SOCKS5] Unknown frame type: %s\n", relay.FrameTypeName(frame.Type))
		}
	}
}

// handleConnectOK processes CONNECT_OK frame
func (s *Server) handleConnectOK(frame *relay.Frame) {
	s.streamMu.RLock()
	pc, ok := s.pendingConns[frame.StreamID]
	s.streamMu.RUnlock()

	if ok && pc != nil {
		select {
		case pc.ready <- nil:
		default:
		}
	}
}

// handleConnectFail processes CONNECT_FAIL frame
func (s *Server) handleConnectFail(frame *relay.Frame) {
	s.streamMu.RLock()
	pc, ok := s.pendingConns[frame.StreamID]
	s.streamMu.RUnlock()

	if ok && pc != nil {
		reason := string(frame.Payload)
		select {
		case pc.ready <- fmt.Errorf("connection failed: %s", reason):
		default:
		}
	}
}

// handleData processes DATA frame - writes data to SOCKS5 client
func (s *Server) handleData(frame *relay.Frame) {
	s.streamMu.RLock()
	conn, ok := s.activeStreams[frame.StreamID]
	s.streamMu.RUnlock()

	if ok && conn != nil {
		_, err := conn.Write(frame.Payload)
		if err != nil {
			if s.config.Debug {
				fmt.Printf("[SOCKS5] Failed to write to client streamID=%d: %v\n", frame.StreamID, err)
			}
		} else {
			atomic.AddUint64(&s.bytesRelayed, uint64(len(frame.Payload)))
		}
	}
}

// handleClose processes CLOSE frame
func (s *Server) handleClose(frame *relay.Frame) {
	s.streamMu.Lock()
	conn, ok := s.activeStreams[frame.StreamID]
	if ok {
		delete(s.activeStreams, frame.StreamID)
	}
	s.streamMu.Unlock()

	if conn != nil {
		conn.Close()
	}

	if s.config.Debug {
		fmt.Printf("[SOCKS5] Stream closed by server streamID=%d\n", frame.StreamID)
	}
}

// directConnect makes a direct TCP connection to the target
// Uses the physical interface to avoid routing loop through TUN
func (s *Server) directConnect(conn net.Conn, target string) error {
	// Get physical interface IP from environment or use default gateway interface
	// This MUST be set to avoid routing loop when TUN captures all traffic
	physicalIP := os.Getenv("WHISPERA_PHYSICAL_IP")
	if physicalIP == "" {
		// Try to detect from VPN server route (should be excluded from TUN)
		physicalIP = detectPhysicalInterfaceIP()
	}

	var localAddr net.Addr
	if physicalIP != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(physicalIP), Port: 0}
		logger.Info("[SOCKS5] Using physical interface %s for %s", physicalIP, target)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		LocalAddr: localAddr,
	}

	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		logger.Error("[SOCKS5] Failed to connect to %s: %v", target, err)
		return err
	}
	defer targetConn.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}

// detectPhysicalInterfaceIP tries to find the physical interface IP
// by enumerating all interfaces and excluding TUN/virtual ones
func detectPhysicalInterfaceIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		logger.Error("[SOCKS5] Failed to enumerate interfaces: %v", err)
		return ""
	}

	var candidates []string

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip virtual/TUN interfaces by name
		nameLower := strings.ToLower(iface.Name)
		isVirtual := strings.Contains(nameLower, "tun") ||
			strings.Contains(nameLower, "tap") ||
			strings.Contains(nameLower, "whispera") ||
			strings.Contains(nameLower, "socks5") ||
			strings.Contains(nameLower, "tunnel") ||
			strings.Contains(nameLower, "wintun") ||
			strings.Contains(nameLower, "openvpn") ||
			strings.Contains(nameLower, "vmware") ||
			strings.Contains(nameLower, "virtualbox")

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip IPv6, loopback, and non-routable
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}

			ipStr := ip.String()

			// Skip known TUN/virtual IPs
			if strings.HasPrefix(ipStr, "10.0.85.") ||
				strings.HasPrefix(ipStr, "10.0.0.") || // Common TUN
				strings.HasPrefix(ipStr, "198.18.") ||
				strings.HasPrefix(ipStr, "169.254.") { // Link-local
				continue
			}

			logger.Info("[SOCKS5] Found interface: %s (%s) IP=%s virtual=%v",
				iface.Name, nameLower, ipStr, isVirtual)

			// Prefer physical interfaces with 192.168.x.x (most common home network)
			if !isVirtual && strings.HasPrefix(ipStr, "192.168.") {
				logger.Info("[SOCKS5] Selected physical interface: %s (%s)", ipStr, iface.Name)
				return ipStr
			}

			// Keep as candidate
			if !isVirtual {
				candidates = append(candidates, ipStr)
			}
		}
	}

	// Return first candidate if no preferred found
	if len(candidates) > 0 {
		logger.Info("[SOCKS5] Using candidate interface: %s", candidates[0])
		return candidates[0]
	}

	logger.Warn("[SOCKS5] No physical interface found!")
	return ""
}

// HealthCheck returns health status
func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()

	s.streamMu.RLock()
	status.Details["pending_streams"] = len(s.pendingConns)
	status.Details["active_streams"] = len(s.activeStreams)
	s.streamMu.RUnlock()

	status.Details["connect_success"] = atomic.LoadUint64(&s.connectSuccess)
	status.Details["connect_failed"] = atomic.LoadUint64(&s.connectFailed)
	status.Details["bytes_relayed"] = atomic.LoadUint64(&s.bytesRelayed)

	return status
}
