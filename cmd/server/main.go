package main

import (
	"whispera/internal/log"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"whispera/internal/server"

	_ "go.uber.org/automaxprocs"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/proxy"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/lifecycle"
	"whispera/internal/db"
	bridgeagent "whispera/internal/modules/bridge"
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/stats"
	"whispera/internal/update"

	"whispera/internal/modules/apiserver"
	"whispera/internal/modules/bot"
	"whispera/internal/modules/bridgepool"
	modconfig "whispera/internal/modules/config"
	"whispera/internal/modules/crypto"
	"whispera/internal/modules/dataplane"
	"whispera/internal/modules/handshake"
	"whispera/internal/modules/keylimits"
	"whispera/internal/modules/metricscollector"
	"whispera/internal/modules/mlserver"
	"whispera/internal/modules/probedetector"
	"whispera/internal/modules/relay"
	"whispera/internal/modules/router"
	"whispera/internal/modules/session"
	"whispera/internal/modules/transport/chameleon"
	_ "whispera/internal/modules/transport/grpc"
	"whispera/internal/modules/transport/tcp"
	"whispera/internal/modules/transport/udp"
	mlpkg "whispera/internal/obfuscation/ml"
	"whispera/pkg/wiraid"
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

var globalProbeDetector *probedetector.Detector

func defaultRouteIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
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
	clusterAddr    = flag.String("cluster-addr", ":8082", "Bridge cluster HTTP listen address (served by bridge agent)")
	selfAddr       = flag.String("self-addr", "", "Public address of this bridge node (host:port), used in cluster election")
)

var globalBridgePool *bridgepool.Registry
var globalWiraidEngine *wiraid.Engine

var globalKeyLimits = keylimits.New(keylimits.Limits{
	MaxActiveSessions: 10,
	GlobalCap:         10000,
	SoftIPCap:         50,
	BurstPerMinute:    0,
	SessionTTL:        30 * time.Minute,
})

var (
	globalHandshake      *handshake.Handler
	globalDataPlane      *dataplane.Processor
	globalSessionMgr     *session.Manager
	globalUDPTransport   *udp.Transport
	globalRelay          *relay.Server
	globalObfuscator     interfaces.Obfuscator
	globalCryptoProvider interfaces.CryptoProvider
	globalServerConfig   *modconfig.ServerConfig
	globalBridgeAgent    *bridgeagent.Agent
	globalBridge         *relay.Bridge
	globalRouter         *router.Engine
	globalCorrelation    *evasion.CorrelationDefense
	globalUpdater        *update.Updater

	activeListeners = make(map[string]net.Listener)
	listenersMutex  sync.RWMutex

	portH2CChans   = make(map[string]chan net.Conn)
	portH2CChansMu sync.Mutex
)

var udpIPRate struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	lastClean time.Time
}

func init() {
	udpIPRate.seen = make(map[string]time.Time)
	udpIPRate.lastClean = time.Now()
}

func udpIPRateAllow(addr net.Addr) bool {
	ip := addr.String()
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}

	udpIPRate.mu.Lock()
	defer udpIPRate.mu.Unlock()

	now := time.Now()
	if now.Sub(udpIPRate.lastClean) > time.Minute {
		for k, v := range udpIPRate.seen {
			if now.Sub(v) > 5*time.Second {
				delete(udpIPRate.seen, k)
			}
		}
		udpIPRate.lastClean = now
	}

	if last, ok := udpIPRate.seen[ip]; ok && now.Sub(last) < 200*time.Millisecond {
		return false
	}
	udpIPRate.seen[ip] = now
	return true
}

func StartInbound(inbound modconfig.InboundConfig, serverConfig *modconfig.ServerConfig) error {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()
	if _, exists := activeListeners[inbound.Tag]; exists {
		return fmt.Errorf("inbound %s already running", inbound.Tag)
	}

	listenAddr := fmt.Sprintf("%s:%d", inbound.Listen, inbound.Port)

	if serverConfig.Chameleon.Enabled {
		if _, chmPort, err := net.SplitHostPort(serverConfig.Chameleon.ListenAddr); err == nil && chmPort != "" && strconv.Itoa(inbound.Port) == chmPort {
			return nil
		}
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	activeListeners[inbound.Tag] = listener

	go func() {
		defer func() {
			listenersMutex.Lock()
			delete(activeListeners, inbound.Tag)
			listenersMutex.Unlock()
		}()

		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				continue
			}

			var peek [3]byte
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _ := io.ReadFull(conn, peek[:])
			conn.SetReadDeadline(time.Time{})

			pConn := &prependConn{Conn: conn, prepend: peek[:n]}

			portH2CChansMu.Lock()
			h2cCh, hasH2C := portH2CChans[listenAddr]
			portH2CChansMu.Unlock()

			if hasH2C && n == 3 && peek[0] == 'P' && peek[1] == 'R' && peek[2] == 'I' {
				select {
				case h2cCh <- pConn:
				default:
					pConn.Close()
				}
				continue
			}

			go handleTCPConnection(pConn, globalHandshake)
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

	if err := listener.Close(); err != nil {
		return fmt.Errorf("failed to close listener %s: %w", tag, err)
	}

	delete(activeListeners, tag)
	return nil
}

func StartReverseInbound(inbound modconfig.InboundConfig, stopCh <-chan struct{}) {
	remoteAddr := inbound.RemoteAddr

	if remoteAddr == "" {
		return
	}

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		conn, err := (&net.Dialer{Timeout: 1 * time.Second}).DialContext(context.Background(), "tcp", remoteAddr)

		if err != nil {
			select {
			case <-stopCh:
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}

		backoff = 2 * time.Second

		if globalRelay != nil {
			if globalHandshake != nil {
				handleTCPConnection(conn, globalHandshake)
			} else {
				globalRelay.ServeTunnel(stats.WrapConn(conn, conn.RemoteAddr().String()), false)
			}
		} else {
			conn.Close()
		}
	}
}

func acceptBackoff(d *time.Duration) {
	time.Sleep(*d)
	if *d < time.Second {
		*d *= 2
	}
}

func main() {

	if len(os.Args) > 1 {

		cmd := strings.TrimSpace(os.Args[1])

		switch cmd {
		case "x25519":
			private := make([]byte, 32)
			if _, err := rand.Read(private); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			public, err := curve25519.X25519(private, curve25519.Basepoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key: %s\n", base64.StdEncoding.EncodeToString(private))
			fmt.Printf("Public Key:  %s\n", base64.StdEncoding.EncodeToString(public))
			os.Exit(0)
		case "pubkey":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "whispera pubkey <private_key>")
				os.Exit(1)
			}
			privateKeyString := strings.TrimSpace(os.Args[2])

			private, err := base64.StdEncoding.DecodeString(privateKeyString)

			if err != nil || len(private) != 32 {
				fmt.Fprintf(os.Stderr, "Error: invalid private key (must be 32 bytes Base64)\n")
				os.Exit(1)
			}
			pub, _ := curve25519.X25519(private, curve25519.Basepoint)
			fmt.Println(base64.StdEncoding.EncodeToString(pub))
			os.Exit(0)
		case "create-admin":
			createAdminCmd := flag.NewFlagSet("create-admin", flag.ExitOnError)
			email := createAdminCmd.String("email", "", "Admin email")
			password := createAdminCmd.String("password", "", "Admin password")
			dbURL := createAdminCmd.String("db", "", "PostgreSQL URL")

			createAdminCmd.Parse(os.Args[2:])

			if *email == "" || *password == "" || *dbURL == "" {
				fmt.Fprintln(os.Stderr, "whispera create-admin -email <email> -password <pass> -db <postgres_url>")
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
		case "hash-password":
			if len(os.Args) < 3 || os.Args[2] == "" {
				fmt.Fprintln(os.Stderr, "Usage: whispera hash-password <password>")
				os.Exit(1)
			}
			h, err := bcrypt.GenerateFromPassword([]byte(os.Args[2]), bcrypt.DefaultCost)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(string(h))
			os.Exit(0)
		case "wiraid":
			runWiraidCLI(os.Args[2:])
			os.Exit(0)
		case "update-checksum":
			cfgPath := "/etc/whispera/config.yaml"
			if len(os.Args) >= 3 {
				cfgPath = os.Args[2]
			}
			p, err := modconfig.New(cfgPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			if err := p.UpdateChecksum(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update checksum: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Checksum updated successfully")
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

	runtime.SetBlockProfileRate(10000)
	runtime.SetMutexProfileFraction(100)

	go func() {
		if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
		}
	}()

	if *debug {
		log.SetLevel(logger.LevelDebug)
	}

	if *printVersion {
		os.Exit(0)
	}

	manager := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30_000_000_000,
		GracefulStop:    true,
	})

	memWatchdog := base.NewMemoryWatchdog(512, 1024, 30*time.Second)
	memWatchdog.Start()
	manager.OnShutdown(func() { memWatchdog.Stop() })

	moduleCtx, moduleCancel := context.WithCancel(context.Background())
	manager.OnShutdown(moduleCancel)

	if err := createModules(manager, moduleCtx); err != nil {
		log.Fatalf("Failed to create modules: %v", err)
	}

	if globalServerConfig != nil && globalServerConfig.NATS.Enabled && globalServerConfig.NATS.URL != "" {
		prefix := globalServerConfig.NATS.Prefix
		if prefix == "" {
			prefix = "whispera"
		}
		if natsBus, err := events.NewNATSEventBus(globalServerConfig.NATS.URL, prefix); err == nil {
			manager.Registry().SetEventBus(natsBus)
		}
	}

	if globalServerConfig != nil && globalServerConfig.Bridge.AutoRegister && globalServerConfig.UpstreamServer != "" {

		go func() {

			time.Sleep(1 * time.Second)

			registerBridgeWithMainServer()
		}()
	}

	if *validateConfig {
		os.Exit(0)
	}
	manager.OnStop(func() error {
		if eng := mlpkg.GetNativeEngine(); eng != nil {
			eng.Close()
		}
		return nil
	})

	if err := manager.Run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}

}

func createModules(manager *lifecycle.Manager, ctx context.Context) error {
	configProvider, err := modconfig.New(*configFile)
	if err != nil {
		return err
	}
	if err := manager.Register(configProvider); err != nil {
		return err
	}

	var serverConfig *modconfig.ServerConfig
	if *configFile != "" {
		_ = configProvider.Load(*configFile)
		serverConfig = configProvider.GetConfig()
	} else {
		serverConfig = modconfig.DefaultServerConfig()
	}
	globalServerConfig = serverConfig

	if serverConfig.API.AuthToken == "" && *configFile != "" {
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err == nil {
			newToken := base64.StdEncoding.EncodeToString(tokenBytes)
			if err := configProvider.Update(func(c *modconfig.ServerConfig) {
				c.API.AuthToken = newToken
			}); err == nil {
				serverConfig = configProvider.GetConfig()
				globalServerConfig = serverConfig
			}
		}
	}

	if serverConfig.API.AdminUsername == "admin" && serverConfig.API.AdminPassword == "admin" {
		fmt.Println("The default login and username are not secure and need to be changed:")
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
			return err
		}
		db.SetGlobal(database)
	}
	server.Global.SetCallbacks(
		func(inbound modconfig.InboundConfig) error {
			if inbound.Mode == "reverse" {
				go StartReverseInbound(inbound, ctx.Done())
				return nil
			}
			return StartInbound(inbound, serverConfig)
		},
		func(tag string) error {
			return StopInbound(tag)
		},
	)

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

		bridgeCfg := &relay.BridgeConfig{
			ListenAddr:     serverConfig.Server.ListenAddr,
			UpstreamServer: serverConfig.UpstreamServer,
		}

		bridge, err := relay.NewBridge(bridgeCfg)
		if err != nil {
			return fmt.Errorf("failed to create bridge: %w", err)
		}

		bridge.OnFailover(func(active bool) {
			if !active {
				fmt.Printf("bridge is offline\n")
			}
		})

		globalBridge = bridge

		if err := bridge.Start(serverConfig.Server.ListenAddr); err != nil {
			return fmt.Errorf("failed to start bridge: %w", err)
		}

		agentCfg := bridgeagent.DefaultAgentConfig()
		agentCfg.BridgeID = serverConfig.Bridge.Region + "-" + serverConfig.Server.ListenAddr
		agentCfg.UpstreamServer = serverConfig.UpstreamServer
		agentCfg.RegistrationToken = serverConfig.Bridge.RegistrationToken
		agentCfg.ClusterListenAddr = *clusterAddr

		if *selfAddr != "" {
			agentCfg.SelfAddress = *selfAddr
		} else {
			agentCfg.SelfAddress = serverConfig.Server.ListenAddr
		}
		globalBridgeAgent = bridgeagent.NewAgent(agentCfg)
		globalBridgeAgent.Start()

		select {}
	}

	if err := initCore(manager, serverConfig); err != nil {
		return err
	}
	if err := initTransports(manager, serverConfig, ctx, configProvider); err != nil {
		return err
	}

	return initOptional(manager, serverConfig, ctx)
}

func initCore(m *lifecycle.Manager, sc *modconfig.ServerConfig) error {
	cryptoProvider, err := crypto.New(&crypto.Config{
		DefaultCipher: crypto.CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   100,
	})
	if err != nil {
		return err
	}
	globalCryptoProvider = cryptoProvider
	if err := m.Register(cryptoProvider); err != nil {
		return err
	}

	sessionMgr, err := session.New(&session.Config{
		MaxSessions:     sc.Session.MaxSessions,
		SessionTimeout:  sc.Session.SessionTimeout.D(),
		CleanupInterval: sc.Session.CleanupInterval.D(),
	})
	if err != nil {
		return err
	}
	globalSessionMgr = sessionMgr
	if err := m.Register(sessionMgr); err != nil {
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
	globalRouter = routerEngine
	if err := m.Register(routerEngine); err != nil {
		return err
	}

	if geo := sc.Routing.Geo; geo.Enabled {
		dir := "/var/lib/whispera/geo"
		if geo.GeoIPFile != "" {
			_ = routerEngine.LoadGeoIPFile(geo.GeoIPFile)
		} else if geo.GeoSiteFile != "" {
			_ = routerEngine.LoadGeoSiteFile(geo.GeoSiteFile)
		} else {
			_ = routerEngine.LoadGeoData(dir)
		}
	}

	handshakeHandler, err := handshake.New(&handshake.Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          sc.Session.SessionTimeout.D(),
		MaxPending:       1000,
		EnableAntiReplay: true,
	})
	if err != nil {
		return err
	}
	handshakeHandler.SetDependencies(cryptoProvider, sessionMgr)

	if sc.Server.PrivateKey != "" {
		var privateKey []byte
		privateKey, err = base64.StdEncoding.DecodeString(sc.Server.PrivateKey)
		if err != nil {
			log.Fatalf("Invalid private key in config: %v (only Base64)", err)
		}
		if len(privateKey) != 32 {
			log.Fatalf("Private key only 32 bytes (Base64)")
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			log.Fatalf("Failed to derive public key: %v", err)
		}
		handshakeHandler.SetStaticKeys(publicKey, privateKey)
	}
	globalHandshake = handshakeHandler
	if err := m.Register(handshakeHandler); err != nil {
		return err
	}

	dataPlaneProcessor, err := dataplane.New(&dataplane.Config{
		MTU:                 sc.Server.MTU,
		WorkerCount:         sc.Server.Workers,
		BufferSize:          4096,
		EnableNAT:           true,
		EnableFragmentation: true,
	})
	if err != nil {
		return err
	}
	globalDataPlane = dataPlaneProcessor
	if err := m.Register(dataPlaneProcessor); err != nil {
		return err
	}

	return nil
}

func initTransports(m *lifecycle.Manager, sc *modconfig.ServerConfig, ctx context.Context, cfgProvider *modconfig.Provider) error {
	udpTransport, err := udp.New(&udp.Config{
		ListenAddr:    sc.Transport.UDP.ListenAddr,
		MaxPacketSize: sc.Transport.UDP.MaxPacketSize,
		WorkerCount:   sc.Transport.UDP.Workers,
		BufferSize:    sc.Transport.UDP.BufferSize,
	})
	if err != nil {
		return err
	}
	udpTransport.OnPacket(handlePacket)
	globalUDPTransport = udpTransport
	if err := m.Register(udpTransport); err != nil {
		return err
	}

	relayServer, err := relay.New(&relay.Config{
		MaxStreams:     sc.Relay.MaxStreams,
		EnableTCP:      sc.Relay.EnableTCP,
		EnableUDP:      sc.Relay.EnableUDP,
		Debug:          sc.Relay.Debug || *debug,
		UpstreamProxy:  sc.Relay.UpstreamProxy,
		PaddingMaxSize: sc.Obfuscation.Padding.MaxSize,
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
	relayServer.SetRouter(globalRouter)

	if om := globalDataPlane.GetOutboundManager(); om != nil {
		relayServer.SetOutboundDial(om.Dial)
		om.UpdateOutbounds(sc.Outbounds)
		outboundsCh := cfgProvider.Watch("outbounds")
		go func() {
			for val := range outboundsCh {
				if outbounds, ok := val.([]modconfig.OutboundConfig); ok {
					om.UpdateOutbounds(outbounds)
				}
			}
		}()
	}

	if err := m.Register(relayServer); err != nil {
		return err
	}

	if len(sc.Inbounds) > 0 {
		for _, inbound := range sc.Inbounds {
			if inbound.Mode == "reverse" {
				ib := inbound
				go StartReverseInbound(ib, ctx.Done())
				continue
			}
			if inbound.Port == 0 {
				continue
			}
			if err := StartInbound(inbound, sc); err != nil {
			}
		}
	} else {
		if sc.Transport.TCP.Enabled {
			tcpTransport, err := tcp.New(&tcp.Config{
				ListenAddr:   sc.Transport.TCP.ListenAddr,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				KeepAlive:    30 * time.Second,
				MaxConns:     10000,
				BufferSize:   32 * 1024,
			})
			if err != nil {
				return err
			}
			if err := m.Register(tcpTransport); err != nil {
				return err
			}
			go func() {
				time.Sleep(1 * time.Second)
				backoffTCP := 1 * time.Millisecond
				for {
					conn, err := tcpTransport.Accept()
					if err != nil {
						acceptBackoff(&backoffTCP)
						continue
					}
					backoffTCP = 1 * time.Millisecond
					go handleTCPConnection(conn, globalHandshake)
				}
			}()
		}
	}

	return nil
}

func initOptional(m *lifecycle.Manager, sc *modconfig.ServerConfig, ctx context.Context) error {
	if sc.Metrics.Enabled {
		metricsCollector, err := metricscollector.New(&metricscollector.Config{
			Enabled:    true,
			ListenAddr: sc.Metrics.ListenAddr,
			Path:       sc.Metrics.Path,
		})
		if err != nil {
			return err
		}
		if err := m.Register(metricsCollector); err != nil {
			return err
		}
	}

	if sc.API.Enabled {
		apiServer, err := apiserver.New(&apiserver.Config{
			Enabled:           true,
			ListenAddr:        sc.API.ListenAddr,
			AuthToken:         sc.API.AuthToken,
			WebRoot:           sc.API.WebRoot,
			EnableCORS:        true,
			AdminUsername:     sc.API.AdminUsername,
			AdminPassword:     sc.API.AdminPassword,
			AdminPasswordHash: sc.API.AdminPasswordHash,
			LoginRateLimit:    sc.API.LoginRateLimit,
		})
		if err != nil {
			return err
		}

		apiServer.SetRegistry(m.Registry())
		apiServer.SetKeyLimits(globalKeyLimits)
		globalBridgePool = apiServer.BridgePool()

		if err := m.Register(apiServer); err != nil {
			return err
		}

		apiServer.Handle("/api/bridge/failover", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if globalBridge == nil {
				json.NewEncoder(w).Encode(map[string]interface{}{"mode": "master", "failover": false})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"mode":               "bridge",
				"upstream_alive":     globalBridge.IsUpstreamAlive(),
				"failover_active":    globalBridge.IsFailoverActive(),
				"active_connections": globalBridge.GetActiveConnections(),
			})
		})

		apiServer.Handle("/api/ml/weights", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			snap := mlpkg.GetGlobalSnapshot()
			if snap == nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, `{"error":"weights not ready yet"}`)
				return
			}
			data, err := json.Marshal(snap)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Write(data)
		})

		wiraidBaseDir := os.Getenv("WHISPERA_WIRAID_DIR")
		if wiraidBaseDir == "" {
			wiraidBaseDir = "/var/lib/whispera/wiraid"
		}

		if os.Getenv("WHISPERA_PUBLIC_HOST") == "" && sc.Server.PublicURL != "" {
			if u, err := url.Parse(sc.Server.PublicURL); err == nil && u.Hostname() != "" {
				os.Setenv("WHISPERA_PUBLIC_HOST", u.Hostname())
			}
		}

		if eng, err := wiraid.NewEngine(wiraidBaseDir); err != nil {
		} else {
			globalWiraidEngine = eng
			eng.RegisterRoutes(apiServer.Handle)
			go eng.StartEnabled()
			if globalRelay != nil {
				globalRelay.SetProxyDialer(&wiraidProxyDialer{eng: eng})
			}
		}

		globalProbeDetector = probedetector.New(probedetector.DefaultConfig())
		globalProbeDetector.Start()
		apiServer.SetProbeDetector(globalProbeDetector)
	}

	if sc.Chameleon.Enabled && (sc.Chameleon.TLSCert != "" || sc.Chameleon.Domain != "") {
		ganIface := sc.Chameleon.GANIface
		if ganIface == "" {
			ganIface = defaultRouteIface()
		}
		ganPort := sc.Chameleon.GANPort
		if ganPort == 0 {
			if _, p, err := net.SplitHostPort(sc.Chameleon.ListenAddr); err == nil {
				ganPort, _ = strconv.Atoi(p)
			}
		}
		if ganPort == 0 {
			ganPort = 443
		}
		ganMaxPadding := sc.Chameleon.GANMaxPadding
		if ganMaxPadding == 0 {
			ganMaxPadding = 4096
		}
		ganModelDir := os.Getenv("WHISPERA_ML_MODEL_DIR")
		if ganModelDir == "" {
			ganModelDir = "./ml_models"
		}
		ganSavePath := filepath.Join(ganModelDir, "gan_state.json")
		ganRunner := mlpkg.NewGANRunner(ganIface, ganPort, ganSavePath)

		cCfg := &chameleon.ServerConfig{
			GANDecide: func(iatMean, sizeMean, upRatio float64) chameleon.GANAction {
				a := ganRunner.GAN().Decide(mlpkg.FlowFeatures{
					IATMean:  iatMean,
					SizeMean: sizeMean,
					UpRatio:  upRatio,
				})
				lambda := mlpkg.GANLambda(sc.Obfuscation.ThreatLevel)
				return chameleon.GANAction{
					SleepMs:   a.SleepMs * lambda,
					PaddingN:  int(a.PaddingFrac * float64(ganMaxPadding) * lambda),
					SegShrink: a.SegShrink * lambda,
				}
			},
			ListenAddr:  sc.Chameleon.ListenAddr,
			TLSCert:     sc.Chameleon.TLSCert,
			TLSKey:      sc.Chameleon.TLSKey,
			Domain:      sc.Chameleon.Domain,
			ACMEDir:     sc.Chameleon.ACMEDir,
			DecoyOrigin: sc.Chameleon.DecoyOrigin,
			GetUsers: func() []chameleon.UserEntry {
				registered := apiserver.GetRegisteredUsers()
				entries := make([]chameleon.UserEntry, 0, len(registered))
				for _, u := range registered {
					psk, err := base64.StdEncoding.DecodeString(u.PrivateKey)
					if err != nil || len(psk) != 32 {
						continue
					}
					entries = append(entries, chameleon.UserEntry{UserID: u.UserID, PSK: psk})
				}
				return entries
			},
			OnConn: func(conn net.Conn, userID string) {
				mlpkg.FlowRegistry.RegisterConn(conn.LocalAddr(), conn.RemoteAddr(), mlpkg.FlowTunnel)
				tracked := stats.WrapConn(conn, userID)
				go func() {
					globalRelay.ServeTunnelRaw(tracked, false)
					mlpkg.FlowRegistry.DeleteConn(conn.LocalAddr(), conn.RemoteAddr())
				}()
			},
		}
		cCfg.QUICListenAddr = sc.Chameleon.QUICListenAddr
		go func() { _ = chameleon.ListenAndServe(ctx, cCfg) }()
	}

	if sc.Bot.Enabled && db.IsEnabled() {
		botModule, err := bot.New(&sc.Bot, db.Global())
		if err != nil {
			return err
		}
		if globalWiraidEngine != nil {
			botModule.SetWiraidEngine(globalWiraidEngine)
		}
		if globalBridgePool != nil {
			botModule.SetBridgePool(globalBridgePool)
		}
		if err := m.Register(botModule); err != nil {
			return err
		}
	}

	if sc.Correlation.Enabled {
		corrCfg := &evasion.CorrelationConfig{
			Enabled:         true,
			PaddingEnabled:  sc.Correlation.PaddingEnabled,
			MixEnabled:      sc.Correlation.JitterEnabled,
			ConstantRatePPS: sc.Correlation.RateBytesPerSec,
		}
		if sc.Correlation.MaxJitterMs > 0 {
			corrCfg.DelayJitter = time.Duration(sc.Correlation.MaxJitterMs) * time.Millisecond
		} else {
			corrCfg.DelayJitter = 50 * time.Millisecond
		}
		if corrCfg.ConstantRatePPS <= 0 {
			corrCfg.ConstantRatePPS = 100
		}
		globalCorrelation = evasion.NewCorrelationDefense(corrCfg)
		m.OnShutdown(func() { globalCorrelation.Stop() })
	}

	mlListenAddr := ":8000"
	if sc.ML.ListenAddr != "" {
		mlListenAddr = sc.ML.ListenAddr
	}
	mlServer, err := mlserver.New(&mlserver.Config{
		ListenAddr: mlListenAddr,
		Token:      sc.API.AuthToken,
		DataDir:    "./ml_data",
	})
	if err != nil {
		return err
	}
	if err := m.Register(mlServer); err != nil {
		return err
	}
	os.Setenv("WHISPERA_ML_SERVER", "http://"+mlListenAddr)

	if sc.Update.Enabled && sc.Update.ManifestURL != "" {
		updateConfig := &update.Config{
			ManifestURL:    sc.Update.ManifestURL,
			CurrentVersion: Version,
			CheckInterval:  sc.Update.CheckInterval.D(),
		}
		if updateConfig.CheckInterval <= 0 {
			updateConfig.CheckInterval = 1 * time.Hour
		}
		binaryPath, _ := os.Executable()
		updateConfig.BinaryPath = binaryPath
		globalUpdater = update.NewUpdater(updateConfig)
		globalUpdater.Start()
		m.OnShutdown(func() { globalUpdater.Stop() })
	}

	return nil
}

func handlePacket(data []byte, addr net.Addr) {

	ctx := context.Background()

	if len(data) >= 32 && len(data) <= 96 && globalHandshake != nil {

		if !udpIPRateAllow(addr) {
			return
		}

		sess, err := globalHandshake.HandleHandshake(ctx, data, addr)

		if err == nil && sess != nil {

			if response := globalHandshake.BuildResponse(sess); response != nil {
				if globalUDPTransport != nil {
					if _, err := globalUDPTransport.WriteTo(response, addr); err != nil {
						return
					}
				}
			}
			return
		}
	}

	if globalSessionMgr == nil {
		return
	}

	sess, _ := globalSessionMgr.GetSessionByAddr(addr)

	payload := data

	if globalObfuscator != nil {

		deobfuscated, _, err := globalObfuscator.Process(data, interfaces.DirectionInbound)

		if err == nil && len(deobfuscated) > 0 {
			payload = deobfuscated
		}
	}

	if globalCorrelation != nil {

		payload = globalCorrelation.ProcessInbound(payload)

		if len(payload) == 0 {
			return
		}

		if len(payload) >= 1 && payload[0] == 0xFF {
			return
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
					return
				}
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
			return
		}
	}
}

func handleTCPConnection(conn net.Conn, hsHandler *handshake.Handler) {

	defer conn.Close()

	addr := conn.RemoteAddr()

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	var firstByte [1]byte

	if _, err := io.ReadFull(conn, firstByte[:]); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	if hsHandler != nil && firstByte[0] == byte(handshake.HandshakeTypeInit) {

		rest := make([]byte, 63)

		if _, err := io.ReadFull(conn, rest); err != nil {
			return
		}

		padLen := int(rest[62])

		buf := append(firstByte[:], rest...)

		if padLen > 0 && padLen <= 32 {

			extra := make([]byte, padLen)

			if _, err := io.ReadFull(conn, extra); err == nil {
				buf = append(buf, extra...)
			}
		}

		sess, err := hsHandler.HandleHandshake(context.Background(), buf, addr)
		if err != nil {
			return
		}

		if response := hsHandler.BuildResponse(sess); response != nil {
			if _, err := conn.Write(response); err != nil {
				return
			}
		}

		if globalRelay != nil {
			globalRelay.ServeTunnel(stats.WrapConn(conn, addr.String()), false)
		}
	} else {
		logger.Trace().Infow("raw_tcp_no_handshake",
			"remote", addr.String(),
			"first_byte", fmt.Sprintf("0x%02x", firstByte[0]),
		)

		if globalRelay != nil {
			globalRelay.ServeTunnel(stats.WrapConn(&prependConn{Conn: conn, prepend: []byte{firstByte[0]}}, addr.String()), false)
		}
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
		return fmt.Errorf("UDP not available")
	}

	n, err := w.transport.WriteTo(payload, w.addr)

	if err == nil && n > 0 && w.UserID != "" {
		stats.AddTx(w.UserID, int64(n))
	}

	return err
}

func (w *UDPResponseWriter) RemoteAddr() net.Addr { return w.addr }

func registerBridgeWithMainServer() {

	cfg := globalServerConfig

	if cfg == nil {
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

	address := fmt.Sprintf("%s", port)

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
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}

	url := fmt.Sprintf("https://%s/api/bridge-register", cfg.UpstreamServer)

	requestContentType, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))

	requestContentType.Header.Set("Content-Type", "application/json")

	responce, err := client.Do(requestContentType)

	if err != nil {

		url = fmt.Sprintf("http://%s/api/bridge-register", cfg.UpstreamServer)

		newRequest, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))

		newRequest.Header.Set("Content-Type", "application/json")

		responce, err = client.Do(newRequest)
	}

	if err != nil {
		return
	}

	defer responce.Body.Close()

	if responce.StatusCode != http.StatusOK {
		return
	}
}

type wiraidProxyDialer struct {
	eng *wiraid.Engine
}

func (d *wiraidProxyDialer) Dial(network, addr string) (net.Conn, error) {

	host, portStr, err := net.SplitHostPort(addr)

	if err == nil {

		var port64 uint64

		fmt.Sscanf(portStr, "%d", &port64)

		if socksAddr, ok := d.eng.MatchRoute(host, uint16(port64)); ok {

			socks, errSocks := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)

			if errSocks == nil {
				return socks.Dial(network, addr)
			}
		}
	}
	return proxy.Direct.Dial(network, addr)
}
