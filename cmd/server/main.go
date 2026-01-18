// Package main is the entry point for the Whispera modular server
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" // Register pprof handlers
	"os"
	"time"

	"golang.org/x/crypto/curve25519"

	"whispera/internal/core/interfaces"
	"whispera/internal/core/lifecycle"
	"whispera/internal/core/registry"
	"whispera/internal/logger"

	// Modules
	"whispera/internal/modules/apiserver"
	modconfig "whispera/internal/modules/config"
	"whispera/internal/modules/crypto"
	"whispera/internal/modules/dataplane"
	"whispera/internal/modules/handshake"
	"whispera/internal/modules/metricscollector"
	"whispera/internal/modules/obfuscator"
	"whispera/internal/modules/phantom"
	"whispera/internal/modules/relay"
	"whispera/internal/modules/router"
	"whispera/internal/modules/session"
	"whispera/internal/modules/transport/tcp"
	"whispera/internal/modules/transport/udp"
	ws "whispera/internal/modules/transport/websocket"
)

// log is the module logger
var log = logger.Module("server")

// Version information (set at build time)
var (
	Version   = "2.1.3"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// prependConn wraps a net.Conn and prepends already-read data to future reads
type prependConn struct {
	net.Conn
	prepend []byte
}

func (c *prependConn) Read(b []byte) (int, error) {
	if len(c.prepend) > 0 {
		n := copy(b, c.prepend)
		c.prepend = c.prepend[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// Command line flags
var (
	configFile     = flag.String("config", "", "Path to configuration file")
	listenAddr     = flag.String("listen", "", "UDP/TCP listen address (default from config)")
	apiAddr        = flag.String("api", ":8080", "API server listen address")
	metricsAddr    = flag.String("metrics", ":9090", "Metrics server listen address")
	debug          = flag.Bool("debug", false, "Enable debug logging")
	printVersion   = flag.Bool("version", false, "Print version and exit")
	validateConfig = flag.Bool("validate-config", false, "Validate configuration and exit")
	pprofAddr      = flag.String("pprof", "localhost:6060", "Pprof server listen address")
)

// Global module references for packet handler
var (
	globalHandshake    *handshake.Handler
	globalDataPlane    *dataplane.Processor
	globalSessionMgr   *session.Manager
	globalUDPTransport *udp.Transport
	globalTCPTransport *tcp.Transport
	globalRelay        *relay.Server
	globalObfuscator   interfaces.Obfuscator
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[PANIC] Whispera Server: %v\n", r)
			os.Exit(2)
		}
	}()

	fmt.Println("[DEBUG] Whispera Server: main() started")
	flag.Parse()

	// Default to config.yaml if not specified to allow persistence
	if *configFile == "" {
		*configFile = "config.yaml"
	}

	fmt.Printf("[DEBUG] Whispera Server: flags parsed, config=%s\n", *configFile)

	// Start pprof server
	go func() {
		fmt.Printf("[DEBUG] Starting pprof server on %s\n", *pprofAddr)
		if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
			fmt.Printf("[WARN] Failed to start pprof server: %v\n", err)
		}
	}()

	if *debug {
		logger.SetLevel(logger.LevelDebug)
	}

	if *printVersion {
		log.Printf("Whispera Server v%s (built %s, commit %s)", Version, BuildTime, GitCommit)
		os.Exit(0)
	}

	log.Printf("╔══════════════════════════════════════════════════════════════╗")
	log.Printf("║           Whispera Modular Server v%s                    ║", Version)
	log.Printf("╚══════════════════════════════════════════════════════════════╝")

	// Create lifecycle manager
	manager := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30_000_000_000, // 30 seconds
		GracefulStop:    true,
	})

	// Register module factories
	registerFactories()

	// Create and register modules
	if err := createModules(manager); err != nil {
		log.Fatalf("Failed to create modules: %v", err)
	}

	// Setup event handlers
	setupEventHandlers(manager)

	// Validate config if requested
	if *validateConfig {
		log.Println("✓ Configuration validated successfully")
		os.Exit(0)
	}

	// Run the application
	fmt.Println("[DEBUG] Whispera Server: starting lifecycle manager")
	if err := manager.Run(); err != nil {
		fmt.Printf("[ERROR] Whispera Server: application error: %v\n", err)
		log.Fatalf("Application error: %v", err)
	}

	log.Println("Server shutdown complete")
}

func registerFactories() {
	registry.GlobalFactoryRegistry.RegisterFactory("transport.udp", udp.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("transport.websocket", ws.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("session.manager", session.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("routing.engine", router.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("obfuscation.engine", obfuscator.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("crypto.provider", crypto.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("handshake.handler", handshake.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("dataplane.processor", dataplane.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("metrics.collector", metricscollector.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("api.server", apiserver.Factory)
	registry.GlobalFactoryRegistry.RegisterFactory("phantom.handler", phantom.Factory)
}

func createModules(manager *lifecycle.Manager) error {
	fmt.Println("[DEBUG] Whispera Server: createModules() started")
	// 1. Config Provider
	configProvider, err := modconfig.New(*configFile)
	if err != nil {
		return err
	}
	if err := manager.Register(configProvider); err != nil {
		return err
	}

	// Load configuration
	var serverConfig *modconfig.ServerConfig
	if *configFile != "" {
		fmt.Printf("[DEBUG] Whispera Server: loading config from %s\n", *configFile)
		if err := configProvider.Load(*configFile); err != nil {
			log.Printf("⚠ Warning: Failed to load config file: %v, using defaults", err)
		}
		serverConfig = configProvider.GetConfig()
	} else {
		fmt.Println("[DEBUG] Whispera Server: using default config")
		serverConfig = modconfig.DefaultServerConfig()
	}

	// Apply command line overrides
	if *listenAddr != "" {
		serverConfig.Transport.UDP.ListenAddr = *listenAddr
		// Sync Server ListenAddr (TCP/Phantom) to match UDP if flag provided
		serverConfig.Server.ListenAddr = *listenAddr
	}
	if *apiAddr != "" {
		serverConfig.API.ListenAddr = *apiAddr
	}
	if *metricsAddr != "" {
		serverConfig.Metrics.ListenAddr = *metricsAddr
	}

	// 2. Crypto Provider
	cryptoProvider, err := crypto.New(&crypto.Config{
		DefaultCipher: crypto.CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   100,
	})
	if err != nil {
		return err
	}
	if err := manager.Register(cryptoProvider); err != nil {
		return err
	}

	// 3. Session Manager
	sessionMgr, err := session.New(&session.Config{
		MaxSessions:     serverConfig.Session.MaxSessions,
		SessionTimeout:  serverConfig.Session.SessionTimeout,
		CleanupInterval: serverConfig.Session.CleanupInterval,
	})
	if err != nil {
		return err
	}
	globalSessionMgr = sessionMgr
	if err := manager.Register(sessionMgr); err != nil {
		return err
	}

	// 4. Router
	routerEngine, err := router.New(&router.Config{
		MaxRules:    1000,
		EnableCache: true,
		CacheSize:   10000,
	})
	if err != nil {
		return err
	}
	if err := manager.Register(routerEngine); err != nil {
		return err
	}

	// 5. Obfuscator
	obfuscatorEngine, err := obfuscator.New(&obfuscator.Config{
		DefaultProfile: serverConfig.Obfuscation.Profile,
		ThreatLevel:    serverConfig.Obfuscation.ThreatLevel,
	})
	if err != nil {
		return err
	}
	globalObfuscator = obfuscatorEngine
	if err := manager.Register(obfuscatorEngine); err != nil {
		return err
	}

	// 6. Handshake Handler
	handshakeHandler, err := handshake.New(&handshake.Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          serverConfig.Session.SessionTimeout,
		MaxPending:       1000,
		EnableAntiReplay: true,
	})
	if err != nil {
		return err
	}
	handshakeHandler.SetDependencies(cryptoProvider, sessionMgr)

	// Set static keys from config
	if serverConfig.Server.PrivateKey != "" {
		fmt.Println("[DEBUG] Whispera Server: processing private key from config")
		privKey, err := hex.DecodeString(serverConfig.Server.PrivateKey)
		if err != nil {
			fmt.Printf("[ERROR] Whispera Server: invalid hex in private key: %v\n", err)
			log.Fatalf("Invalid private key in config: %v", err)
		}
		if len(privKey) != 32 {
			fmt.Printf("[ERROR] Whispera Server: private key length is %d, expected 32\n", len(privKey))
			log.Fatalf("Private key must be 32 bytes (hex encoded)")
		}

		pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
		if err != nil {
			fmt.Printf("[ERROR] Whispera Server: failed to derive public key: %v\n", err)
			log.Fatalf("Failed to derive public key: %v", err)
		}

		fmt.Printf("[DEBUG] Whispera Server: loaded static key pair (Public: %x)\n", pubKey)
		handshakeHandler.SetStaticKeys(pubKey, privKey)
	}

	globalHandshake = handshakeHandler
	if err := manager.Register(handshakeHandler); err != nil {
		return err
	}

	// 7. Data Plane
	dataPlaneProcessor, err := dataplane.New(&dataplane.Config{
		MTU:                 serverConfig.Server.MTU,
		WorkerCount:         serverConfig.Server.Workers,
		BufferSize:          4096,
		EnableNAT:           true,
		EnableFragmentation: true,
	})
	if err != nil {
		return err
	}
	dataPlaneProcessor.SetDependencies(routerEngine, obfuscatorEngine, sessionMgr)
	globalDataPlane = dataPlaneProcessor
	if err := manager.Register(dataPlaneProcessor); err != nil {
		return err
	}

	// 8. UDP Transport
	udpTransport, err := udp.New(&udp.Config{
		ListenAddr:    serverConfig.Transport.UDP.ListenAddr,
		MaxPacketSize: serverConfig.Transport.UDP.MaxPacketSize,
		WorkerCount:   serverConfig.Transport.UDP.Workers,
		BufferSize:    serverConfig.Transport.UDP.BufferSize,
	})
	if err != nil {
		return err
	}
	udpTransport.OnPacket(handlePacket)
	globalUDPTransport = udpTransport // Set global for sending responses
	if err := manager.Register(udpTransport); err != nil {
		return err
	}

	// 8.1. TCP Transport
	if serverConfig.Transport.TCP.Enabled {
		tcpTransport, err := tcp.New(&tcp.Config{
			ListenAddr:   serverConfig.Transport.TCP.ListenAddr, // Use TCP-specific address
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			KeepAlive:    30 * time.Second,
			MaxConns:     10000,
			BufferSize:   32 * 1024,
		})
		if err != nil {
			return err
		}
		globalTCPTransport = tcpTransport
		if err := manager.Register(tcpTransport); err != nil {
			return err
		}

		// Start accepting TCP connections in background
		go func() {
			// Wait for start
			time.Sleep(1 * time.Second)
			log.Printf("[TCP] Starting accept loop on %s", serverConfig.Transport.TCP.ListenAddr)

			for {
				conn, err := tcpTransport.Accept()
				if err != nil {
					if serverConfig.Relay.Debug {
						log.Printf("[TCP] Accept error: %v", err)
					}
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// Handle connection in new goroutine
				go handleTCPConnection(conn)
			}
		}()
		log.Printf("  ✓ TCP Transport enabled on %s", serverConfig.Transport.TCP.ListenAddr)
	}

	// 8.2. WebSocket Transport
	if serverConfig.Transport.WebSocket.Enabled {
		wsTransport, err := ws.New(&ws.Config{
			ListenAddr: serverConfig.Transport.WebSocket.ListenAddr,
			Path:       serverConfig.Transport.WebSocket.Path,
			MaxConns:   10000,
		})
		if err != nil {
			return err
		}
		if err := manager.Register(wsTransport); err != nil {
			return err
		}

		// Start accepting WebSocket connections in background
		go func() {
			// Wait for start
			time.Sleep(1 * time.Second)
			log.Printf("[WS] Starting accept loop on %s%s", serverConfig.Transport.WebSocket.ListenAddr, serverConfig.Transport.WebSocket.Path)

			for {
				conn, err := wsTransport.Accept()
				if err != nil {
					if serverConfig.Relay.Debug {
						log.Printf("[WS] Accept error: %v", err)
					}
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// Handle connection in new goroutine using existing TCP handler
				// WebSocket provides a net.Conn interface that wraps frames, so logic matches
				go handleTCPConnection(conn)
			}
		}()
	}

	// 8.5. Relay Server (for client traffic relay to internet)
	relayServer, err := relay.New(&relay.Config{
		MaxStreams:    serverConfig.Relay.MaxStreams,
		EnableTCP:     serverConfig.Relay.EnableTCP,
		EnableUDP:     serverConfig.Relay.EnableUDP,
		Debug:         serverConfig.Relay.Debug || *debug,
		UpstreamProxy: serverConfig.Relay.UpstreamProxy,
	})
	if err != nil {
		return err
	}
	// Set transport callback so relay can send responses back to clients
	relayServer.SetTransport(func(data []byte, addr net.Addr) error {
		// Apply obfuscation if enabled (CRITICAL FIX: Client expects obfuscated traffic)
		payload := data
		if globalObfuscator != nil {
			obfuscated, _, err := globalObfuscator.Process(data, interfaces.DirectionOutbound)
			if err != nil {
				return fmt.Errorf("failed to obfuscate relay frame: %w", err)
			}
			payload = obfuscated
			if *debug {
				fmt.Printf("[Relay] Obfuscated response %d -> %d bytes for %v\n", len(data), len(payload), addr)
			}
		}

		// Check address type to determine transport
		if _, ok := addr.(*net.TCPAddr); ok && globalTCPTransport != nil {
			// Find connection by remote address is hard without tracking map
			// For now relay server doesn't track TCP connections well
			// TODO: Implement better TCP connection tracking
			return fmt.Errorf("TCP response not implemented yet")
		}

		if globalUDPTransport != nil {
			_, err := globalUDPTransport.WriteTo(payload, addr)
			return err
		}
		return nil
	})
	globalRelay = relayServer
	if err := manager.Register(relayServer); err != nil {
		return err
	}
	log.Printf("  ✓ Relay server enabled (TCP+UDP)")

	// 9. Metrics Collector
	if serverConfig.Metrics.Enabled {
		metricsCollector, err := metricscollector.New(&metricscollector.Config{
			Enabled:    true,
			ListenAddr: serverConfig.Metrics.ListenAddr,
			Path:       serverConfig.Metrics.Path,
		})
		if err != nil {
			return err
		}
		if err := manager.Register(metricsCollector); err != nil {
			return err
		}
	}

	// 10. API Server
	if serverConfig.API.Enabled {
		apiServer, err := apiserver.New(&apiserver.Config{
			Enabled:    true,
			ListenAddr: serverConfig.API.ListenAddr,
			AuthToken:  serverConfig.API.AuthToken,
			WebRoot:    serverConfig.API.WebRoot,
			EnableCORS: true,
		})
		if err != nil {
			return err
		}
		apiServer.SetRegistry(manager.Registry())
		if err := manager.Register(apiServer); err != nil {
			return err
		}
	}

	// 11. Phantom Handler (SNI masquerading / TLS proxy)
	// Auto-generate keys if missing (Critical for REALITY authentication)
	if serverConfig.Phantom.PrivateKey == "" {
		log.Println("Phantom: No Private Key found. Auto-generating new X25519 key pair...")
		privKey, pubKey, err := phantom.GenerateKeyPair()
		if err != nil {
			log.Printf("Error generating keys: %v", err)
		} else {
			// Save to config
			updateErr := configProvider.Update(func(cfg *modconfig.ServerConfig) {
				cfg.Phantom.PrivateKey = hex.EncodeToString(privKey)
				// Also ensure it is enabled if we are generating keys, implying intent to use?
				// Better to leave enabled state as is, but defaults are often false.
			})
			if updateErr != nil {
				log.Printf("Error saving generated key to config: %v", updateErr)
			} else {
				log.Printf("✓ Phantom Keys Generated and Saved to config.yaml")
				log.Printf("  PRIVATE KEY: %s", hex.EncodeToString(privKey))
				log.Printf("================================================================")
				log.Printf("  PUBLIC KEY:  %s", hex.EncodeToString(pubKey))
				log.Printf("  (COPY THIS KEY to your CLIENT configuration!)")
				log.Printf("================================================================")
			}
		}
	}

	if serverConfig.Phantom.Enabled {
		phantomHandler, err := phantom.New(&phantom.Config{
			Enabled:     true,
			ListenAddr:  serverConfig.Server.ListenAddr, // Use same port as main server
			Dest:        serverConfig.Phantom.Dest,
			ServerNames: serverConfig.Phantom.ServerNames,
			PrivateKey:  serverConfig.Phantom.PrivateKey,
			ShortIds:    serverConfig.Phantom.ShortIds,
			MaxTimeDiff: serverConfig.Phantom.MaxTimeDiff,
			Fingerprint: serverConfig.Phantom.Fingerprint,
			OnAuthenticated: func(conn net.Conn, clientID string) {
				log.Printf("Phantom: Client authenticated: %s", clientID)

				if globalRelay == nil {
					log.Printf("Phantom: Relay server not available, closing connection from %s", clientID)
					conn.Close()
					return
				}

				// SIMPLIFIED: Skip protocol handshake for Phantom connections.
				// Phantom already authenticates via REALITY-like HMAC in the ClientHello.
				// The additional protocol handshake was causing synchronization issues
				// (double handshake, EOF errors, frame corruption).
				// Client now also skips the handshake when EnablePhantom is true.

				log.Printf("Phantom: Starting relay for %s (no extra handshake - REALITY auth sufficient)", clientID)

				// Pass to relay - client will start sending framed data immediately
				// Pass nil for obfuscator because Phantom connections use TLS masquerade.
				// The client sets isTransportSecure=true and does NOT obfuscate outbound data.
				globalRelay.ServeTunnel(conn, nil)
			},
		})
		if err != nil {
			log.Printf("⚠ Warning: Failed to create Phantom handler: %v", err)
		} else {
			if err := manager.Register(phantomHandler); err != nil {
				return err
			}
			log.Printf("  ✓ Phantom protocol enabled (dest: %s)", serverConfig.Phantom.Dest)
		}
	}

	log.Printf("✓ Registered %d modules", len(manager.Registry().GetAll()))
	return nil
}

// handlePacket processes incoming UDP packets
func handlePacket(data []byte, addr net.Addr) {
	fmt.Printf("[Packet] Received %d bytes from %v\n", len(data), addr)
	ctx := context.Background()

	// Try handshake first for small packets (32-96 bytes are handshake range)
	if len(data) >= 32 && len(data) <= 96 && globalHandshake != nil {
		sess, err := globalHandshake.HandleHandshake(ctx, data, addr)
		if err == nil && sess != nil {
			if *debug {
				log.Printf("[Packet] Handshake completed for %v, session: %d", addr, sess.ID())
			}
			// Send handshake response back to client
			if response := globalHandshake.BuildResponse(sess); response != nil {
				if globalUDPTransport != nil {
					if _, err := globalUDPTransport.WriteTo(response, addr); err != nil {
						if *debug {
							log.Printf("[Packet] Failed to send handshake response: %v", err)
						}
					} else if *debug {
						log.Printf("[Packet] Sent handshake response (%d bytes) to %v", len(response), addr)
					}
				}
			}
			return
		}
	}

	// Get session for this address
	if globalSessionMgr == nil {
		return
	}

	sess, ok := globalSessionMgr.GetSessionByAddr(addr)
	if !ok {
		if *debug {
			// Enhanced debugging for "No session" issue
			log.Printf("[Packet] No session for %v (Total sessions: %d), dropping packet",
				addr, globalSessionMgr.Count())
		}
		return
	}

	// Try deobfuscation first if obfuscator is active
	payload := data
	if globalObfuscator != nil {
		deobfuscated, _, err := globalObfuscator.Process(data, interfaces.DirectionInbound)
		if err == nil && len(deobfuscated) > 0 {
			payload = deobfuscated
			// fmt.Printf("[Packet] Deobfuscated %d -> %d bytes\n", len(data), len(payload))
		}
	}

	if len(payload) >= 8 && globalRelay != nil {
		// Check if frame type is valid relay protocol (0x01-0x08)
		frameType := payload[2]
		if frameType >= 0x01 && frameType <= 0x08 {
			dataLen := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
			if int(dataLen) <= len(payload)-8 {
				// Create writer
				writer := &UDPResponseWriter{
					transport:  globalUDPTransport,
					addr:       addr,
					obfuscator: globalObfuscator,
					debug:      *debug,
				}

				// Process through relay server
				if err := globalRelay.ProcessFrame(payload, sess, writer); err != nil {
					if *debug {
						log.Printf("[Packet] Relay error: %v", err)
					}
				}
				return
			}
		}
	}

	// Fallback: Process through data plane (for legacy VPN packets)
	if globalDataPlane != nil {
		packet := &interfaces.Packet{
			SessionID: sess.ID(),
			Payload:   payload,
			SrcAddr:   addr,
		}
		if err := globalDataPlane.ProcessInbound(context.Background(), packet, sess); err != nil {
			if *debug {
				log.Printf("[Packet] Data plane error: %v", err)
			}
		}
	}
}

// handleTCPConnection processes an incoming TCP connection
func handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	addr := conn.RemoteAddr()
	if *debug {
		log.Printf("[TCP] New connection from %v", addr)
	}

	// Create writer
	writer := &TCPResponseWriter{
		conn:       conn,
		obfuscator: globalObfuscator,
		debug:      *debug,
	}

	// Buffer for reading
	buf := make([]byte, 32*1024)

	for {
		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(300 * time.Second))

		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				if *debug {
					log.Printf("[TCP] Read error from %v: %v", addr, err)
				}
			}
			return
		}

		data := buf[:n]

		// [FIX] Try handshake first (Raw, non-obfuscated)
		// This is required because client sends raw handshake packet and waits for response.
		// UDP handler has this, but TCP handler was missing it.
		if len(data) >= 32 && len(data) <= 96 && globalHandshake != nil {
			sess, err := globalHandshake.HandleHandshake(context.Background(), data, addr)
			if err == nil && sess != nil {
				if *debug {
					log.Printf("[TCP] Handshake completed for %v", addr)
				}
				// Send response back
				if response := globalHandshake.BuildResponse(sess); response != nil {
					if _, err := conn.Write(response); err != nil {
						if *debug {
							log.Printf("[TCP] Failed to send handshake response: %v", err)
						}
					}
				}
				continue
			}
		}

		// 1. De-obfuscate
		payload := data
		if globalObfuscator != nil {
			deobfuscated, _, err := globalObfuscator.Process(data, interfaces.DirectionInbound)
			if err == nil && len(deobfuscated) > 0 {
				payload = deobfuscated
				if *debug {
					fmt.Printf("[TCP] Deobfuscated %d -> %d bytes from %v\n", len(data), len(payload), addr)
				}
			} else {
				// Failed to deobfuscate - packet might be garbage or attack
				// But maybe obfuscator expects frame alignment?
				// For TCP stream, obfuscator needs state.
				// globalObfuscator is likely stateless (XOR/ChaCha packet based).
				continue
			}
		}

		// 2. Process Relay Frame
		// Check for Relay Frame
		if len(payload) >= 8 && globalRelay != nil {
			// Try to process one or more frames in the buffer
			// TCP stream might contain multiple frames or partial frames
			// For simplicity assume message framing matches (client sends packet = frame)
			// TODO: Implement proper framing buffer for TCP

			if err := globalRelay.ProcessFrame(payload, nil, writer); err != nil {
				if *debug {
					log.Printf("[TCP] Relay process error: %v", err)
				}
			}
		}
	}
}

// UDP Response Writer
type UDPResponseWriter struct {
	transport  *udp.Transport
	addr       net.Addr
	obfuscator interfaces.Obfuscator
	debug      bool
}

func (w *UDPResponseWriter) Write(data []byte) error {
	payload := data
	if w.obfuscator != nil {
		obfuscated, _, err := w.obfuscator.Process(data, interfaces.DirectionOutbound)
		if err != nil {
			return fmt.Errorf("obfuscation failed: %w", err)
		}
		payload = obfuscated
	}
	// Verify transport is available
	if w.transport == nil {
		return fmt.Errorf("UDP transport not available")
	}
	_, err := w.transport.WriteTo(payload, w.addr)
	return err
}

func (w *UDPResponseWriter) RemoteAddr() net.Addr { return w.addr }

// TCP Response Writer
type TCPResponseWriter struct {
	conn       net.Conn
	obfuscator interfaces.Obfuscator
	debug      bool
}

func (w *TCPResponseWriter) Write(data []byte) error {
	payload := data
	if w.obfuscator != nil {
		obfuscated, _, err := w.obfuscator.Process(data, interfaces.DirectionOutbound)
		if err != nil {
			return fmt.Errorf("obfuscation failed: %w", err)
		}
		payload = obfuscated
	}
	_, err := w.conn.Write(payload)
	return err
}

func (w *TCPResponseWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }

func setupEventHandlers(manager *lifecycle.Manager) {
	eventBus := manager.Events()

	// Module lifecycle events
	moduleStarted := eventBus.Subscribe("module.started")
	go func() {
		for event := range moduleStarted {
			log.Printf("  ✓ Module started: %s", event.Source)
		}
	}()

	moduleStopped := eventBus.Subscribe("module.stopped")
	go func() {
		for event := range moduleStopped {
			log.Printf("  ○ Module stopped: %s", event.Source)
		}
	}()

	// Debug session events
	if *debug {
		sessionEvents := eventBus.Subscribe("session.*")
		go func() {
			for event := range sessionEvents {
				log.Printf("[Session] %s: %v", event.Type, event.Data)
			}
		}()
	}

	// Handshake stats
	handshakeEvents := eventBus.Subscribe("handshake.*")
	go func() {
		count := 0
		for range handshakeEvents {
			count++
			if count%100 == 0 {
				log.Printf("[Stats] Processed %d handshakes", count)
			}
		}
	}()

	manager.OnStart(func() error {
		log.Println("Initializing server components...")
		return nil
	})

	manager.OnReload(func() error {
		log.Println("Reloading configuration...")
		return nil
	})

	manager.OnShutdown(func() {
		log.Println("Cleanup complete")
	})
}
