package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"whispera/internal/cache"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/lifecycle"
	"whispera/internal/db"
	"whispera/internal/logger"
	"whispera/internal/server/dynamic"
	"whispera/internal/stats"

	"whispera/internal/modules/apiserver"
	"whispera/internal/modules/bot"
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
	_ "whispera/internal/modules/transport/grpc"
	h2c_transport "whispera/internal/modules/transport/h2c"
	"whispera/internal/modules/transport/tcp"
	"whispera/internal/modules/transport/udp"
	_ "whispera/internal/modules/transport/vkwebrtc"
	_ "whispera/internal/modules/transport/websocket"
)

var log = logger.Module("server")

var (
	Version   = "2.1.6"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

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

var (
	configFile     = flag.String("config", "", "Path to configuration file")
	listenAddr     = flag.String("listen", "", "UDP/TCP listen address (default from config)")
	apiAddr        = flag.String("api", ":8080", "API server listen address")
	metricsAddr    = flag.String("metrics", ":9091", "Metrics server listen address")
	debug          = flag.Bool("debug", false, "Enable debug logging")
	printVersion   = flag.Bool("version", false, "Print version and exit")
	validateConfig = flag.Bool("validate-config", false, "Validate configuration and exit")
	pprofAddr      = flag.String("pprof", "localhost:6060", "Pprof server listen address")
)

var (
	globalHandshake      *handshake.Handler
	globalDataPlane      *dataplane.Processor
	globalSessionMgr     *session.Manager
	globalUDPTransport   *udp.Transport
	globalTCPTransport   *tcp.Transport
	globalRelay          *relay.Server
	globalObfuscator     interfaces.Obfuscator
	globalCryptoProvider interfaces.CryptoProvider
	globalServerConfig   *modconfig.ServerConfig

	activeListeners = make(map[string]net.Listener)
	listenersMutex  sync.RWMutex
)

func createHandshakeHandler(privateKeyStr string, serverConfig *modconfig.ServerConfig) *handshake.Handler {
	if privateKeyStr == "" {
		return nil
	}

	h, err := handshake.New(&handshake.Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          serverConfig.Session.SessionTimeout.D(),
		MaxPending:       1000,
		EnableAntiReplay: true,
	})
	if err != nil {
		log.Printf("⚠ Failed to create handshake handler: %v", err)
		return nil
	}

	h.SetDependencies(globalCryptoProvider, globalSessionMgr)

	privKey, err := base64.StdEncoding.DecodeString(privateKeyStr)

	if err != nil || len(privKey) != 32 {
		log.Printf("⚠ Invalid private key: %v (must be 32 bytes Base64)", err)
		return nil
	}

	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		log.Printf("⚠ Failed to derive public key: %v", err)
		return nil
	}

	h.SetStaticKeys(pubKey, privKey)
	return h
}

func StartInbound(inbound modconfig.InboundConfig, serverConfig *modconfig.ServerConfig) error {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()
	if _, exists := activeListeners[inbound.Tag]; exists {
		return fmt.Errorf("inbound %s already running", inbound.Tag)
	}

	listenAddr := fmt.Sprintf("%s:%d", inbound.Listen, inbound.Port)
	network := inbound.StreamSettings.Network

	log.Printf("🚀 [Dynamic] Starting inbound %s (%s) on %s", inbound.Tag, network, listenAddr)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	var hsHandler *handshake.Handler
	var phantomHandler *phantom.Handler

	isPhantom := inbound.StreamSettings.Security == "phantom" || inbound.StreamSettings.Security == "reality"

	if network == "ws" {
		path := inbound.StreamSettings.WS.Path
		if path == "" {
			path = "/ws"
		}
	}

	if isPhantom {
		pPrivKey := inbound.StreamSettings.Phantom.PrivateKey
		if pPrivKey == "" {
			pPrivKey = serverConfig.Server.PrivateKey
		}
		pCfg := &phantom.Config{
			Enabled:     true,
			ListenAddr:  listenAddr,
			Dest:        inbound.StreamSettings.Phantom.Dest,
			PrivateKey:  pPrivKey,
			ServerNames: serverConfig.Phantom.ServerNames,
			ShortIds:    serverConfig.Phantom.ShortIds,
			MaxTimeDiff: serverConfig.Phantom.MaxTimeDiff,
			Fingerprint: serverConfig.Phantom.Fingerprint,
			OnAuthenticated: func(conn net.Conn, clientID string) {
				log.Printf("[Dynamic-Phantom] Authenticated: %s on inbound %s", clientID, inbound.Tag)
				if globalRelay != nil {
					var session interfaces.Session
					if globalSessionMgr != nil {
						params := interfaces.SessionParams{
							ClientAddr: conn.RemoteAddr(),
							UserID:     clientID,
							Metadata: map[string]interface{}{
								"user_id":       clientID,
								"inbound_tag":   inbound.Tag,
								"protocol":      "phantom",
								"authenticated": true,
								"created_at":    time.Now(),
							},
						}

						sess, err := globalSessionMgr.CreateSession(params)
						if err != nil {
							log.Printf("⚠ Failed to create session for phantom client %s: %v", clientID, err)
						} else {
							session = sess
							log.Printf("  + Session created: %d (User: %s)", session.ID(), clientID)
							defer session.Close()
						}
					}
					globalRelay.ServeTunnel(conn, nil)
				} else {
					conn.Close()
				}
			},
		}

		if pCfg.Dest == "" {
			pCfg.Dest = serverConfig.Phantom.Dest
		}

		var err error
		phantomHandler, err = phantom.New(pCfg)
		if err != nil {
			listener.Close()
			return fmt.Errorf("failed to create phantom handler: %w", err)
		}
		log.Printf("  ✨ [Dynamic] Enabled Phantom/Reality on inbound %s", inbound.Tag)

	} else {
		privKey := ""
		if inbound.StreamSettings.Phantom.PrivateKey != "" {
			privKey = inbound.StreamSettings.Phantom.PrivateKey
		} else if serverConfig.Server.PrivateKey != "" {
			privKey = serverConfig.Server.PrivateKey
		}

		if privKey != "" {
			hsHandler = createHandshakeHandler(privKey, serverConfig)
			if hsHandler == nil {
				listener.Close()
				return fmt.Errorf("failed to create handshake handler for %s", inbound.Tag)
			}
		}
	}

	if network == "h2c" {
		h2cConfig := &h2c_transport.Config{
			ListenAddr:           listenAddr,
			Path:                 "/",
			MaxConcurrentStreams: 1000,
		}

		h2cTrans, err := h2c_transport.New(h2cConfig)
		if err != nil {
			listener.Close()
			return fmt.Errorf("failed to create h2c transport: %w", err)
		}

		listener.Close()

		if err := h2cTrans.Listen(listenAddr); err != nil {
			return fmt.Errorf("failed to listen h2c on %s: %w", listenAddr, err)
		}

		log.Printf("✅ [Dynamic] Inbound %s listening on %s (H2C)", inbound.Tag, listenAddr)

		go func() {
			defer func() {
				h2cTrans.Close()
				log.Printf("⏹ [Dynamic] Stopped inbound %s (H2C)", inbound.Tag)
			}()

			for {
				conn, err := h2cTrans.Accept()
				if err != nil {
					log.Printf("⚠ [Dynamic] H2C Accept error on %s: %v", inbound.Tag, err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if globalRelay != nil {
					go globalRelay.ServeTunnel(conn, nil)
				} else {
					conn.Close()
				}
			}
		}()
		return nil
	}

	activeListeners[inbound.Tag] = listener

	go func() {
		defer func() {
			listenersMutex.Lock()
			delete(activeListeners, inbound.Tag)
			listenersMutex.Unlock()
			log.Printf("⏹ [Dynamic] Stopped inbound %s", inbound.Tag)
		}()

		log.Printf("✅ [Dynamic] Inbound %s listening on %s", inbound.Tag, listenAddr)

		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Printf("⚠ [Dynamic] Accept error on %s: %v", inbound.Tag, err)
				continue
			}

			if phantomHandler != nil {
				go phantomHandler.HandleConnection(conn)
			} else {
				go handleTCPConnection(conn, hsHandler)
			}
		}
	}()

	return nil
}

func StopInbound(tag string) error {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	listener, exists := activeListeners[tag]
	if !exists {
		return fmt.Errorf("inbound %s not running", tag)
	}

	log.Printf("🛑 [Dynamic] Stopping inbound %s...", tag)

	if err := listener.Close(); err != nil {
		return fmt.Errorf("failed to close listener %s: %w", tag, err)
	}

	delete(activeListeners, tag)
	return nil
}

func main() {
	if len(os.Args) > 1 {
		cmd := strings.TrimSpace(os.Args[1])
		switch cmd {
		case "x25519":
			priv, pub, err := phantom.GenerateKeyPair()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key: %s\n", base64.StdEncoding.EncodeToString(priv))
			fmt.Printf("Public Key:  %s\n", base64.StdEncoding.EncodeToString(pub))
			os.Exit(0)
		case "pubkey":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "Usage: whispera pubkey <private_key>")
				os.Exit(1)
			}
			privKeyStr := strings.TrimSpace(os.Args[2])
			var priv []byte
			var err error

			priv, err = base64.StdEncoding.DecodeString(privKeyStr)

			if err != nil || len(priv) != 32 {
				fmt.Fprintf(os.Stderr, "Error: invalid private key (must be 32 bytes Base64)\n")
				os.Exit(1)
			}
			pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
			fmt.Println(base64.StdEncoding.EncodeToString(pub))
			os.Exit(0)
		case "create-admin":
			createAdminCmd := flag.NewFlagSet("create-admin", flag.ExitOnError)
			email := createAdminCmd.String("email", "", "Admin email")
			password := createAdminCmd.String("password", "", "Admin password")
			dbURL := createAdminCmd.String("db", "", "PostgreSQL URL")

			createAdminCmd.Parse(os.Args[2:])

			if *email == "" || *password == "" || *dbURL == "" {
				fmt.Fprintln(os.Stderr, "Usage: whispera create-admin -email <email> -password <pass> -db <postgres_url>")
				os.Exit(1)
			}

			cfg := db.DefaultConfig()
			cfg.URL = *dbURL
			database, err := db.New(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to connect to DB: %v\n", err)
				os.Exit(1)
			}
			defer database.Close()

			ctx := context.Background()
			user, err := database.GetUserByEmail(ctx, *email)
			if err != nil {
				user, err = database.CreateUser(ctx, *email, *password, 0, nil, "http2", "browser", "vk", "", "")
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to create user: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("User %s created\n", *email)
			} else {
				if err := database.UpdateUser(ctx, user.ID, *email, *password); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to update password: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("User %s password updated\n", *email)
			}

			if err := database.SetAdmin(ctx, user.ID, true); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to set admin: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("User %s is now an admin\n", *email)
			os.Exit(0)
		}
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[PANIC] Whispera Server: %v\n", r)
			os.Exit(2)
		}
	}()

	flag.Parse()

	if *configFile == "" {
		*configFile = "config.yaml"
	}

	if *debug {
		go func() {
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Printf("Failed to start pprof server: %v", err)
			}
		}()
	}

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

	manager := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30_000_000_000,
		GracefulStop:    true,
	})

	if err := createModules(manager); err != nil {
		log.Fatalf("Failed to create modules: %v", err)
	}
	if globalServerConfig != nil && globalServerConfig.Bridge.AutoRegister && globalServerConfig.UpstreamServer != "" {
		go func() {
			time.Sleep(2 * time.Second)
			registerBridgeWithMainServer()
		}()
	}

	setupEventHandlers(manager)

	if *validateConfig {
		log.Println("✓ Configuration validated successfully")
		os.Exit(0)
	}
	if err := manager.Run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}

	log.Println("Server shutdown complete")
}

func createModules(manager *lifecycle.Manager) error {
	configProvider, err := modconfig.New(*configFile)
	if err != nil {
		return err
	}
	if err := manager.Register(configProvider); err != nil {
		return err
	}

	var serverConfig *modconfig.ServerConfig
	if *configFile != "" {
		if err := configProvider.Load(*configFile); err != nil {
			log.Printf("⚠ Warning: Failed to load config file: %v, using defaults", err)
		}
		serverConfig = configProvider.GetConfig()
	} else {
		serverConfig = modconfig.DefaultServerConfig()
	}
	globalServerConfig = serverConfig
	if serverConfig.API.AdminUsername == "admin" && serverConfig.API.AdminPassword == "admin" {
		fmt.Println("")
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║  ⚠️  WARNING: DEFAULT ADMIN CREDENTIALS DETECTED!           ║")
		fmt.Println("║  Username: admin / Password: admin                          ║")
		fmt.Println("║                                                             ║")
		fmt.Println("║  Change admin_username and admin_password in config.yaml     ║")
		fmt.Println("║  before deploying to production!                            ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Println("")
	}

	cacheInstance := cache.New(serverConfig.Cache.RedisURL)
	cache.SetGlobal(cacheInstance)
	if serverConfig.Cache.RedisURL != "" {
		log.Printf("✅ Redis cache initialized: %s", serverConfig.Cache.RedisURL)
	} else {
		log.Printf("✅ In-memory cache initialized (no Redis URL)")
	}

	if serverConfig.Database.PostgresURL != "" {
		dbCfg := db.DefaultConfig()
		dbCfg.URL = serverConfig.Database.PostgresURL
		if serverConfig.Database.MaxConns > 0 {
			dbCfg.MaxConns = int32(serverConfig.Database.MaxConns)
		}
		if serverConfig.Database.MinConns > 0 {
			dbCfg.MinConns = int32(serverConfig.Database.MinConns)
		}

		database, err := db.New(dbCfg)
		if err != nil {
			log.Printf("⚠ PostgreSQL not available: %v (user management disabled)", err)
		} else {
			db.SetGlobal(database)
			log.Printf("✅ PostgreSQL connected (user management enabled)")
		}
	} else {
		log.Printf("ℹ PostgreSQL not configured (user management disabled)")
	}

	dynamic.Global.SetCallbacks(
		func(inbound modconfig.InboundConfig) error {
			return StartInbound(inbound, serverConfig)
		},
		func(tag string) error {
			return StopInbound(tag)
		},
	)
	log.Printf("✅ Dynamic inbound manager initialized")

	if *listenAddr != "" {
		serverConfig.Transport.UDP.ListenAddr = *listenAddr
		serverConfig.Server.ListenAddr = *listenAddr
	}
	if *apiAddr != "" {
		serverConfig.API.ListenAddr = *apiAddr
	}
	if *metricsAddr != "" {
		serverConfig.Metrics.ListenAddr = *metricsAddr
	}

	if serverConfig.RelayMode == "bridge" {
		log.Printf("╔══════════════════════════════════════════════════════════════╗")
		log.Printf("║                  BRIDGE MODE ENABLED                         ║")
		log.Printf("╚══════════════════════════════════════════════════════════════╝")
		log.Printf("  Upstream: %s", serverConfig.UpstreamServer)

		phantomCfg := &phantom.Config{
			Enabled:            true,
			ServerNames:        serverConfig.Phantom.ServerNames,
			PrivateKey:         serverConfig.Phantom.PrivateKey,
			UseRussianService:  serverConfig.Phantom.UseRussianService,
			RussianServiceName: serverConfig.Phantom.RussianService,
		}

		bridgeCfg := &relay.BridgeConfig{
			ListenAddr:     serverConfig.Server.ListenAddr,
			UpstreamServer: serverConfig.UpstreamServer,
			PhantomConfig:  phantomCfg,
		}

		bridge, err := relay.NewBridge(bridgeCfg)
		if err != nil {
			return fmt.Errorf("failed to create bridge: %w", err)
		}

		if err := bridge.Start(serverConfig.Server.ListenAddr); err != nil {
			return fmt.Errorf("failed to start bridge: %w", err)
		}

		log.Printf("✅ Bridge started on %s -> %s", serverConfig.Server.ListenAddr, serverConfig.UpstreamServer)

		select {}
	}

	cryptoProvider, err := crypto.New(&crypto.Config{
		DefaultCipher: crypto.CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   100,
	})
	if err != nil {
		return err
	}
	globalCryptoProvider = cryptoProvider
	if err := manager.Register(cryptoProvider); err != nil {
		return err
	}

	sessionMgr, err := session.New(&session.Config{
		MaxSessions:     serverConfig.Session.MaxSessions,
		SessionTimeout:  serverConfig.Session.SessionTimeout.D(),
		CleanupInterval: serverConfig.Session.CleanupInterval.D(),
	})
	if err != nil {
		return err
	}
	globalSessionMgr = sessionMgr
	if err := manager.Register(sessionMgr); err != nil {
		return err
	}

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

	handshakeHandler, err := handshake.New(&handshake.Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          serverConfig.Session.SessionTimeout.D(),
		MaxPending:       1000,
		EnableAntiReplay: true,
	})
	if err != nil {
		return err
	}
	handshakeHandler.SetDependencies(cryptoProvider, sessionMgr)

	if serverConfig.Server.PrivateKey != "" {
		var privKey []byte
		var err error

		privKey, err = base64.StdEncoding.DecodeString(serverConfig.Server.PrivateKey)

		if err != nil {
			log.Fatalf("Invalid private key in config: %v (must be Base64)", err)
		}
		if len(privKey) != 32 {
			log.Fatalf("Private key must be 32 bytes (Base64)")
		}

		pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
		if err != nil {
			log.Fatalf("Failed to derive public key: %v", err)
		}

		handshakeHandler.SetStaticKeys(pubKey, privKey)
	}

	globalHandshake = handshakeHandler
	if err := manager.Register(handshakeHandler); err != nil {
		return err
	}

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
	globalUDPTransport = udpTransport
	if err := manager.Register(udpTransport); err != nil {
		return err
	}
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
	relayServer.SetTransport(func(data []byte, addr net.Addr) error {
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

		if globalUDPTransport != nil {
			_, err := globalUDPTransport.WriteTo(payload, addr)
			return err
		}
		return nil
	})
	relayServer.SetRawPacketHandler(func(data []byte) error {
		if globalDataPlane != nil {
			return globalDataPlane.InjectPacket(data)
		}
		return fmt.Errorf("dataplane not available")
	})
	globalRelay = relayServer
	if err := manager.Register(relayServer); err != nil {
		return err
	}
	log.Printf("  ✓ Relay server enabled (TCP+UDP+L3)")

	if len(serverConfig.Inbounds) > 0 {
		log.Printf("[Server] Starting %d inbounds...", len(serverConfig.Inbounds))
		for _, inbound := range serverConfig.Inbounds {
			if inbound.Port == 0 {
				continue
			}
			if err := StartInbound(inbound, serverConfig); err != nil {
				log.Printf("⚠ Failed to start inbound %s: %v", inbound.Tag, err)
			}
		}
	} else {
		if serverConfig.Transport.TCP.Enabled {
			tcpTransport, err := tcp.New(&tcp.Config{
				ListenAddr:   serverConfig.Transport.TCP.ListenAddr,
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

			go func() {
				time.Sleep(1 * time.Second)
				log.Printf("[TCP] Starting legacy accept loop on %s", serverConfig.Transport.TCP.ListenAddr)
				for {
					conn, err := tcpTransport.Accept()
					if err != nil {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					go handleTCPConnection(conn, globalHandshake)
				}
			}()
		}
	}

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

	if serverConfig.API.Enabled {
		apiServer, err := apiserver.New(&apiserver.Config{
			Enabled:        true,
			ListenAddr:     serverConfig.API.ListenAddr,
			AuthToken:      serverConfig.API.AuthToken,
			WebRoot:        serverConfig.API.WebRoot,
			EnableCORS:     true,
			AdminUsername:  serverConfig.API.AdminUsername,
			AdminPassword:  serverConfig.API.AdminPassword,
			LoginRateLimit: serverConfig.API.LoginRateLimit,
		})
		if err != nil {
			return err
		}
		apiServer.SetRegistry(manager.Registry())
		if err := manager.Register(apiServer); err != nil {
			return err
		}
	}

	if serverConfig.Bot.Enabled {
		if db.IsEnabled() {
			fmt.Println("[DEBUG] Whispera Server: starting Telegram bot module")
			botModule, err := bot.New(&serverConfig.Bot, db.Global())
			if err != nil {
				log.Printf("⚠ Warning: Failed to create Telegram Bot: %v", err)
			} else {
				if err := manager.Register(botModule); err != nil {
					return err
				}
				log.Printf("  ✓ Telegram Bot enabled (Admin ID: %d)", serverConfig.Bot.AdminID)
			}
		} else {
			log.Printf("ℹ Telegram Bot disabled (requires database)")
		}
	}

	log.Printf("✓ Registered %d modules", len(manager.Registry().GetAll()))
	return nil
}

func handlePacket(data []byte, addr net.Addr) {
	fmt.Printf("[Packet] Received %d bytes from %v\n", len(data), addr)
	ctx := context.Background()

	if len(data) >= 32 && len(data) <= 96 && globalHandshake != nil {
		sess, err := globalHandshake.HandleHandshake(ctx, data, addr)
		if err == nil && sess != nil {
			if *debug {
				log.Printf("[Packet] Handshake completed for %v, session: %d", addr, sess.ID())
			}
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

	if globalSessionMgr == nil {
		return
	}

	sess, ok := globalSessionMgr.GetSessionByAddr(addr)
	if !ok {
		if *debug {
			log.Printf("[Packet] No session for %v (Total sessions: %d), dropping packet",
				addr, globalSessionMgr.Count())
		}
		return
	}

	payload := data
	if globalObfuscator != nil {
		deobfuscated, _, err := globalObfuscator.Process(data, interfaces.DirectionInbound)
		if err == nil && len(deobfuscated) > 0 {
			payload = deobfuscated
		}
	}

	if len(payload) >= 8 && globalRelay != nil {
		frameType := payload[2]
		if frameType >= 0x01 && frameType <= 0x08 {
			dataLen := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
			if int(dataLen) <= len(payload)-8 {
				writer := &UDPResponseWriter{
					transport:  globalUDPTransport,
					addr:       addr,
					obfuscator: globalObfuscator,
					debug:      *debug,
				}

				var userID string
				if val := sess.GetMetadata("user_id"); val != nil {
					userID = val.(string)
					writer.UserID = userID
					stats.AddRx(userID, int64(len(payload)))
				}

				if err := globalRelay.ProcessFrame(payload, sess, writer); err != nil {
					if *debug {
						log.Printf("[Packet] Relay error: %v", err)
					}
				}
				return
			}
		}
	}

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

func handleTCPConnection(conn net.Conn, hsHandler *handshake.Handler) {
	defer conn.Close()

	addr := conn.RemoteAddr()
	if *debug {
		log.Printf("[TCP] New connection from %v", addr)
	}

	if hsHandler != nil {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 64)
		if _, err := io.ReadFull(conn, buf); err != nil {
			if *debug {
				log.Printf("[TCP] Failed to read handshake from %v: %v", addr, err)
			}
			return
		}
		conn.SetReadDeadline(time.Time{})

		sess, err := hsHandler.HandleHandshake(context.Background(), buf, addr)
		if err != nil {
			if *debug {
				log.Printf("[TCP] Handshake failed from %v: %v", addr, err)
			}
			return
		}
		if *debug {
			log.Printf("[TCP] Handshake completed for %v", addr)
		}
		if response := hsHandler.BuildResponse(sess); response != nil {
			if _, err := conn.Write(response); err != nil {
				return
			}
		}
	}

	if globalRelay != nil {
		globalRelay.ServeTunnel(conn, nil)
	}
}

type UDPResponseWriter struct {
	transport  *udp.Transport
	addr       net.Addr
	obfuscator interfaces.Obfuscator
	debug      bool
	UserID     string
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
	if w.transport == nil {
		return fmt.Errorf("UDP transport not available")
	}
	n, err := w.transport.WriteTo(payload, w.addr)
	if err == nil && n > 0 && w.UserID != "" {
		stats.AddTx(w.UserID, int64(n))
	}
	return err
}

func (w *UDPResponseWriter) RemoteAddr() net.Addr { return w.addr }

type TCPResponseWriter struct {
	conn       net.Conn
	obfuscator interfaces.Obfuscator
	debug      bool
	UserID     string
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
	n, err := w.conn.Write(payload)
	if err == nil && n > 0 && w.UserID != "" {
		stats.AddTx(w.UserID, int64(n))
	}
	return err
}

func (w *TCPResponseWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }

func setupEventHandlers(manager *lifecycle.Manager) {
	eventBus := manager.Events()

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

	if *debug {
		sessionEvents := eventBus.Subscribe("session.*")
		go func() {
			for event := range sessionEvents {
				log.Printf("[Session] %s: %v", event.Type, event.Data)
			}
		}()
	}

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

func registerBridgeWithMainServer() {
	cfg := globalServerConfig
	if cfg == nil {
		return
	}

	log.Printf("Registering bridge with main server: %s", cfg.UpstreamServer)

	publicIP := getPublicIP()
	if publicIP == "" {
		log.Printf("⚠ Bridge registration failed: could not determine public IP")
		return
	}

	port := "443"
	if len(cfg.Inbounds) > 0 {
		port = fmt.Sprintf("%d", cfg.Inbounds[0].Port)
	} else if cfg.Server.ListenAddr != "" {
		if _, p, err := net.SplitHostPort(cfg.Server.ListenAddr); err == nil {
			port = p
		}
	}

	address := fmt.Sprintf("%s:%s", publicIP, port)

	reqBody := map[string]string{
		"address":    address,
		"provider":   cfg.Bridge.Provider,
		"region":     cfg.Bridge.Region,
		"public_key": cfg.Server.PrivateKey,
		"type":       cfg.Bridge.Type,
		"token":      cfg.Bridge.RegistrationToken,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("⚠ Bridge registration failed: %v", err)
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf("https://%s/api/bridge-register", cfg.UpstreamServer)
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		url = fmt.Sprintf("http://%s/api/bridge-register", cfg.UpstreamServer)
		resp, err = client.Post(url, "application/json", bytes.NewReader(data))
	}

	if err != nil {
		log.Printf("⚠ Bridge registration failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("⚠ Bridge registration failed: HTTP %d", resp.StatusCode)
		return
	}

	log.Printf("✓ Bridge registered with main server: %s", address)
}

func getPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	services := []string{
		"https://ifconfig.me",
		"https://icanhazip.com",
		"https://api.ipify.org",
	}

	for _, svc := range services {
		resp, err := client.Get(svc)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		ip := strings.TrimSpace(string(buf[:n]))

		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}
