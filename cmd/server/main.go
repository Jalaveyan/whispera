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
	"whispera/internal/modules/transport/udp"
)

// log is the module logger
var log = logger.Module("server")

// Version information (set at build time)
var (
	Version   = "2.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Command line flags
var (
	configFile     = flag.String("config", "", "Path to configuration file")
	listenAddr     = flag.String("listen", "", "UDP listen address (default from config)")
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

	// 8.5. Relay Server (for client traffic relay to internet)
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
				// Handle authenticated Whispera client
				log.Printf("Phantom: Authenticated client %s from %s", clientID, conn.RemoteAddr())

				// Keep connection alive and drain buffer to prevent blocking/RST
				// This ensures the handshake success is verified and connection stays stable
				go func() {
					defer conn.Close()
					buf := make([]byte, 16384) // 16KB buffer
					for {
						// Set generous timeout
						conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
						n, err := conn.Read(buf)
						if err != nil {
							if err != io.EOF {
								log.Printf("Phantom: Connection closed for %s: %v", clientID, err)
							} else {
								log.Printf("Phantom: Client %s disconnected", clientID)
							}
							return
						}
						// Log reception implies successful channel
						// TODO: Inject 'buf[:n]' into globalDataPlane/Relay once TCP framing is defined
						if *debug {
							log.Printf("Phantom: Received %d bytes from %s (Data Plane pending)", n, clientID)
						}
					}
				}()
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

	// Check if this is a relay protocol frame (min 8 bytes header)
	// Relay frames have: [StreamID:2][Type:1][Flags:1][Length:4][Payload:N]

	// Try deobfuscation first if obfuscator is active
	payload := data
	if globalObfuscator != nil {
		deobfuscated, _, err := globalObfuscator.Process(data, interfaces.DirectionInbound)
		if err == nil && len(deobfuscated) > 0 {
			payload = deobfuscated
		}
	}

	if len(payload) >= 8 && globalRelay != nil {
		// Check if frame type is valid relay protocol (0x01-0x08)
		frameType := payload[2]
		// Stricter check to avoid collision with TLS/VPN traffic
		// Relay frames: [StreamID:2][Type:1][Flags:1][Length:4][Payload...]
		// We verify that the Length field matches the remaining data size
		if frameType >= 0x01 && frameType <= 0x08 {
			dataLen := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
			// Allow some buffer, but if claimed length is way larger than packet, it's likely not a relay frame
			if int(dataLen) <= len(payload)-8 {
				// Process through relay server - this handles CONNECT, DATA, etc.
				// Note: We pass the DEOBFUSCATED payload
				if err := globalRelay.ProcessFrame(payload, sess, addr); err != nil {
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
		if err := globalDataPlane.ProcessInbound(ctx, packet, sess); err != nil {
			if *debug {
				log.Printf("[Packet] Data plane error: %v", err)
			}
		}
	}
}

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
