package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"time"

	grpc_transport "whispera/internal/modules/transport/grpc"
	"whispera/internal/modules/transport/okwebrtc"
	quic_transport "whispera/internal/modules/transport/quic"
	shadowtls_transport "whispera/internal/modules/transport/shadowtls"
	"whispera/internal/modules/transport/vkbot"
	"whispera/internal/modules/transport/vkwebrtc"
	ws_transport "whispera/internal/modules/transport/websocket"
	"whispera/internal/modules/transport/yacloud"
	"whispera/internal/modules/transport/yadisk"
	"whispera/internal/modules/transport/yatelemost"
	"whispera/internal/mux"
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/obfuscation/marionette"
	mlpkg "whispera/internal/obfuscation/ml"

	"nhooyr.io/websocket"
)

type dialFn = func(context.Context) (net.Conn, error)

type transportEntry struct {
	name   string
	secure bool
	cond   func(only func(string) bool, m *Manager) bool
	dial   func(m *Manager) dialFn
}

var transportEntries = []transportEntry{
	{
		name: "vkwebrtc", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return only("vkwebrtc") && m.config.VKToken != ""
		},
		dial: func(m *Manager) dialFn { return m.dialVKWebRTC },
	},
	{
		name: "okwebrtc", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return only("okwebrtc") && m.tcfg("ok_token") != ""
		},
		dial: func(m *Manager) dialFn { return m.dialOKWebRTC },
	},
	{
		name: "yatelemost", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return only("yatelemost") && m.tcfg("session_id") != "" && m.tcfg("conference_url") != ""
		},
		dial: func(m *Manager) dialFn { return m.dialYaTelemost },
	},
	{
		name: "yadisk", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return only("yadisk") && m.tcfg("token") != ""
		},
		dial: func(m *Manager) dialFn { return m.dialYaDisk },
	},
	{
		name: "yacloud", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return only("yacloud") && m.tcfg("gateway_url") != ""
		},
		dial: func(m *Manager) dialFn { return m.dialYaCloud },
	},
	{
		name: "vkbot", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return only("vkbot") && m.config.VKBotUserToken != "" && m.config.VKGroupID != 0
		},
		dial: func(m *Manager) dialFn { return m.dialVKBot },
	},
	{
		name: "cdnworker", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return only("cdnworker") && m.config.CDNWorkerURL != ""
		},
		dial: func(m *Manager) dialFn { return m.dialCDNWorker },
	},
	{
		name: "asn_bypass", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return m.asnBypassDialer != nil && m.config.EnableASNBypass
		},
		dial: func(m *Manager) dialFn { return m.dialASNBypass },
	},
	{
		name: "shadowtls", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			return m.config.Transport == "shadowtls" && m.tcfg("password") != "" && m.config.ServerAddrTCP != ""
		},
		dial: func(m *Manager) dialFn { return m.dialShadowTLS },
	},
	{
		name: "quic", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			auto := m.config.Transport == "auto" || m.config.Transport == ""
			return only("quic") || auto
		},
		dial: func(m *Manager) dialFn { return m.dialQUIC },
	},
	{
		name: "websocket", secure: false,
		cond: func(only func(string) bool, m *Manager) bool {
			return m.config.ServerAddrTCP != "" && (only("ws") || only("websocket"))
		},
		dial: func(m *Manager) dialFn { return m.dialWebSocket },
	},
	{
		name: "grpc", secure: false,
		cond: func(only func(string) bool, m *Manager) bool {
			return m.config.ServerAddrTCP != "" && only("grpc")
		},
		dial: func(m *Manager) dialFn { return m.dialGRPC },
	},
	{
		name: "tcp", secure: true,
		cond: func(only func(string) bool, m *Manager) bool {
			if m.config.ServerAddrTCP == "" {
				return false
			}
			auto := m.config.Transport == "auto" || m.config.Transport == ""
			return only("tcp") || auto
		},
		dial: func(m *Manager) dialFn { return m.dialTCP },
	},
}

func (m *Manager) spoofDialer() *net.Dialer {
	if len(m.spoofIPs) == 0 {
		return dohDialer()
	}
	idx := atomic.AddUint64(&m.spoofIdx, 1) % uint64(len(m.spoofIPs))
	localIP := m.spoofIPs[idx]
	if !strings.Contains(localIP, ":") {
		localIP = localIP + ":0"
	}
	localAddr, err := net.ResolveTCPAddr("tcp", localIP)
	if err != nil {
		return dohDialer()
	}
	return &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   10 * time.Second,
		Resolver:  dohDialer().Resolver,
	}
}

func (m *Manager) dialManagedConn(ctx context.Context, id string) (*managedConn, error) {
	if m.tlsAgent != nil && m.asnBypassDialer != nil {
		tlsErrors := int(atomic.LoadInt32(&m.tlsErrStreak))
		profile := m.tlsAgent.Decide(mlpkg.TLSView{
			ConsecutiveTLSErrors: tlsErrors,
			TransportName:        m.config.Transport,
		})
		if profile != "" {
			m.config.TLSFingerprint = profile
		}
	}

	conn, err := m.dial(ctx)
	if err != nil {
		if m.tlsAgent != nil && isHandshakeError(err) {
			streak := atomic.AddInt32(&m.tlsErrStreak, 1)
			m.tlsAgent.RecordOutcome(false)
			m.maybePreemptiveRotate(streak)
		}
		return nil, err
	}

	conn = evasion.NewDesyncConn(conn, m.config.DesyncConfig)

	if m.handshake != nil && !m.config.EnableChameleon {
		sess, err := m.handshake.InitiateHandshake(ctx, conn, conn.RemoteAddr())
		if err != nil {
			conn.Close()
			if m.tlsAgent != nil {
				streak := atomic.AddInt32(&m.tlsErrStreak, 1)
				m.tlsAgent.RecordOutcome(false)
				m.maybePreemptiveRotate(streak)
			}
			return nil, fmt.Errorf("handshake: %w", err)
		}
		if sess != nil {
			atomic.StoreUint32(&m.sessionID, sess.ID())
		}
	}

	if m.tlsAgent != nil {
		atomic.StoreInt32(&m.tlsErrStreak, 0)
		m.tlsAgent.RecordOutcome(true)
	}

	var muxConn net.Conn
	if m.config.EnableChameleon {
		muxConn = conn
	} else {
		padMax := m.config.PaddingMaxSize
		if padMax <= 0 {
			padMax = 128
		}
		muxConn = mux.NewPaddedConn(conn, padMax)
	}
	log.Debug("[dialManagedConn:%s] mux.Client starting", id)
	muxSess, err := mux.Client(muxConn, m.getMuxConfig())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mux: %w", err)
	}
	log.Debug("[dialManagedConn:%s] mux.Client OK, opening control stream", id)

	stream, err := muxSess.OpenStream()
	if err != nil {
		muxSess.Close()
		return nil, fmt.Errorf("open stream: %w", err)
	}
	log.Debug("[dialManagedConn:%s] control stream opened, managedConn ready", id)

	var controlStream net.Conn = stream

	var maxAge time.Duration
	var maxUploadB int64
	if m.config.EnableChameleon {
		maxAge = 0
		maxUploadB = 0
	}

	return &managedConn{
		Conn:       controlStream,
		session:    muxSess,
		id:         id,
		createdAt:  time.Now(),
		maxAge:     maxAge,
		maxUploadB: maxUploadB,
		closing:    make(chan struct{}),
	}, nil
}

func (m *Manager) dial(ctx context.Context) (net.Conn, error) {
	if m.config.CustomDialFn != nil {
		return m.config.CustomDialFn(ctx)
	}

	if dialOne, ok := m.chameleonDial(); ok {
		conn, err := dialOne(ctx)
		if err == nil {
			m.isTransportSecure = true
			return conn, nil
		}
		log.Warn("chameleon dial failed (%v), falling back to standard transports", err)
	}

	candidates := m.buildCandidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no transport candidates configured")
	}

	dialer := func(dctx context.Context) (net.Conn, error) {
		return m.parallelDial(dctx, candidates)
	}

	if cfg := m.config.FlowTableConfig; cfg != nil && cfg.Enabled {
		return evasion.DialWithFlowTableBypass(ctx, dialer, cfg)
	}

	return dialer(ctx)
}

func (m *Manager) tcfg(key string) string {
	if m.config.TransportConfig == nil {
		return ""
	}
	if v, ok := m.config.TransportConfig[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (m *Manager) buildCandidates() []dialCandidate {
	t := m.config.Transport
	auto := t == "auto" || t == ""

	var explicit map[string]bool
	if !auto && strings.Contains(t, ",") {
		explicit = make(map[string]bool)
		for _, part := range strings.Split(t, ",") {
			explicit[strings.TrimSpace(part)] = true
		}
	}

	only := func(name string) bool {
		if auto {
			return true
		}
		if explicit != nil {
			return explicit[name]
		}
		return t == name
	}

	var cc []dialCandidate
	for _, e := range transportEntries {
		if e.cond(only, m) {
			cc = append(cc, dialCandidate{e.name, e.secure, e.dial(m)})
		}
	}

	if m.russianTunneler != nil {
		svc := m.config.RussianService
		if svc == "" && auto {
			services := m.russianTunneler.GetAvailableServices()
			if len(services) > 0 {
				n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(services))))
				svc = services[n.Int64()]
				m.russianTunneler.SetActiveService(svc)
			}
		}
		if svc != "" {
			cc = append(cc, dialCandidate{"russian:" + svc, true, m.dialRussian})
		}
	}

	cc = m.applyTransportPolicy(cc)
	cc = m.filterBlockmapAvoid(cc)

	if m.transportAgent != nil && len(cc) > 0 {
		names := make([]string, len(cc))
		for i, c := range cc {
			names[i] = c.name
		}
		m.transportAgent.SetActivePool(names)
	}

	return cc
}

func (m *Manager) filterBlockmapAvoid(cc []dialCandidate) []dialCandidate {
	v := m.blockAvoid.Load()
	if v == nil {
		return cc
	}
	avoid, _ := v.(map[string]bool)
	if len(avoid) == 0 {
		return cc
	}
	filtered := cc[:0:0]
	for _, c := range cc {
		if !avoid[c.name] {
			filtered = append(filtered, c)
		}
	}
	if len(filtered) == 0 {
		return cc
	}
	return filtered
}

func (m *Manager) applyTransportPolicy(cc []dialCandidate) []dialCandidate {
	if len(m.config.TransportWhitelist) == 0 && len(m.config.TransportBlacklist) == 0 {
		return cc
	}
	whitelist := make(map[string]bool, len(m.config.TransportWhitelist))
	for _, n := range m.config.TransportWhitelist {
		whitelist[strings.TrimSpace(n)] = true
	}
	blacklist := make(map[string]bool, len(m.config.TransportBlacklist))
	for _, n := range m.config.TransportBlacklist {
		blacklist[strings.TrimSpace(n)] = true
	}
	out := cc[:0]
	for _, c := range cc {
		base := c.name
		if i := strings.IndexByte(base, ':'); i > 0 {
			base = base[:i]
		}
		if len(whitelist) > 0 && !whitelist[base] {
			continue
		}
		if blacklist[base] {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (m *Manager) parallelDial(ctx context.Context, candidates []dialCandidate) (net.Conn, error) {
	if len(candidates) == 1 {
		conn, err := candidates[0].fn(ctx)
		if err == nil {
			m.isTransportSecure = candidates[0].secure
		}
		return conn, err
	}

	type result struct {
		conn   net.Conn
		secure bool
		name   string
		err    error
	}

	ch := make(chan result, len(candidates))
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	names := make([]string, len(candidates))
	for i, c := range candidates {
		names[i] = c.name
		c := c
		go func() {
			conn, err := c.fn(ctx2)
			ch <- result{conn, c.secure, c.name, err}
		}()
	}
	log.Info("[dial] racing %d transports: %s", len(candidates), strings.Join(names, ", "))

	var winner result
	var errs []string

	for range candidates {
		res := <-ch
		switch {
		case res.err == nil && winner.conn == nil:
			winner = res
			cancel()
			log.Info("[dial] %s won the race", res.name)
		case res.err == nil && res.conn != nil:
			res.conn.Close()
		case res.err != nil && res.err != context.Canceled && res.err.Error() != "context canceled":
			errs = append(errs, res.name+": "+res.err.Error())
		}
	}

	if winner.conn != nil {
		m.isTransportSecure = winner.secure
		return winner.conn, nil
	}
	return nil, fmt.Errorf("all transports failed: %s", strings.Join(errs, "; "))
}

func (m *Manager) dialVKWebRTC(ctx context.Context) (net.Conn, error) {
	vkCfg := &vkwebrtc.Config{
		VKToken:       m.config.VKToken,
		VKGroupID:     m.config.VKGroupID,
		ServerMode:    false,
		SignalingMode: "vk",
		ICEPolicy:     "relay",
	}
	tr, err := vkwebrtc.New(vkCfg)
	if err != nil {
		return nil, err
	}
	if err := tr.Start(); err != nil {
		return nil, err
	}
	conn, err := tr.Dial(ctx, m.config.ServerAddr)
	if err != nil {
		tr.Stop()
		return nil, err
	}
	return conn, nil
}

func (m *Manager) dialVKBot(ctx context.Context) (net.Conn, error) {
	tr, err := vkbot.New(&vkbot.Config{
		GroupID:    m.config.VKGroupID,
		UserToken:  m.config.VKBotUserToken,
		ServerMode: false,
	})
	if err != nil {
		return nil, err
	}
	if err := tr.Start(); err != nil {
		return nil, err
	}
	conn, err := tr.Dial(ctx, m.config.ServerAddr)
	if err != nil {
		tr.Stop()
		return nil, err
	}
	return conn, nil
}

func (m *Manager) dialCDNWorker(ctx context.Context) (net.Conn, error) {
	wsConn, _, err := websocket.Dial(ctx, m.config.CDNWorkerURL, &websocket.DialOptions{
		Subprotocols: []string{"whispera"},
	})
	if err != nil {
		return nil, fmt.Errorf("cdnworker: %w", err)
	}
	return websocket.NetConn(ctx, wsConn, websocket.MessageBinary), nil
}

func (m *Manager) dialRussian(ctx context.Context) (net.Conn, error) {
	st, err := m.russianTunneler.CreateTunnel(ctx, m.config.ServerAddr)
	if err != nil {
		return nil, err
	}
	return NewRussianConnAdapter(st), nil
}

func (m *Manager) dialASNBypass(ctx context.Context) (net.Conn, error) {
	conn, err := m.asnBypassDialer.DialContext(ctx, "tcp4", m.config.ServerAddr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(20 * time.Second)
	}
	return conn, nil
}

func (m *Manager) dialQUIC(ctx context.Context) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", m.config.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("quic resolve: %w", err)
	}
	sni := m.getRotationSNI()
	alpn := m.tcfg("quic_alpn")
	if alpn == "" {
		alpn = "h3"
	}
	qTrans, err := quic_transport.New(&quic_transport.Config{
		ListenAddr:     ":0",
		MaxConns:       1,
		MaxIdleTimeout: m.config.KeepaliveInterval * 3,
		ALPN:           alpn,
		ServerName:     sni,
	})
	if err != nil {
		return nil, err
	}
	return qTrans.Dial(ctx, udpAddr.String())
}

func (m *Manager) dialTCP(ctx context.Context) (net.Conn, error) {
	conn, err := m.spoofDialer().DialContext(ctx, "tcp4", m.config.ServerAddrTCP)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(20 * time.Second)
	}
	return m.wrapChatFSM(conn), nil
}

func (m *Manager) wrapChatFSM(conn net.Conn) net.Conn {
	if !m.config.EnableChatFSM {
		return conn
	}
	interval := m.config.ChatFSMCoverInterval
	if interval <= 0 {
		interval = 8 * time.Second
	}
	var chatID [4]byte
	_, _ = rand.Read(chatID[:])
	return marionette.NewChatFSMConn(conn, binary.BigEndian.Uint32(chatID[:]), interval)
}

func (m *Manager) dialWebSocket(ctx context.Context) (net.Conn, error) {
	path := m.tcfg("ws_path")
	if path == "" {
		path = "/ws"
	}
	host := m.tcfg("ws_host")
	subproto := m.tcfg("ws_subprotocol")
	useTLS := m.tcfg("ws_tls") == "true" || m.tcfg("ws_tls") == "1"

	target := m.config.ServerAddrTCP

	tr, err := ws_transport.New(&ws_transport.Config{
		ListenAddr:   ":0",
		Path:         path,
		Subprotocol:  subproto,
		HostOverride: host,
		UseTLS:       useTLS,
		ServerName:   m.tcfg("ws_sni"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, target)
}

func (m *Manager) dialGRPC(ctx context.Context) (net.Conn, error) {
	serverName := m.tcfg("grpc_sni")
	if serverName == "" {
		serverName = m.tcfg("sni")
	}
	useTLS := m.tcfg("grpc_tls") != "false"

	tr, err := grpc_transport.New(&grpc_transport.Config{
		ListenAddr:  ":0",
		ServiceName: m.tcfg("grpc_service"),
		UseTLS:      useTLS,
		ServerName:  serverName,
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddrTCP)
}

func (m *Manager) dialShadowTLS(ctx context.Context) (net.Conn, error) {
	tr, err := shadowtls_transport.New(&shadowtls_transport.Config{
		Password:     m.tcfg("password"),
		ShadowServer: m.config.ServerAddrTCP,
		SNI:          m.tcfg("sni"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddrTCP)
}

func (m *Manager) dialYaCloud(ctx context.Context) (net.Conn, error) {
	tr, err := yacloud.New(&yacloud.Config{
		GatewayURL: m.tcfg("gateway_url"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialYaDisk(ctx context.Context) (net.Conn, error) {
	tr, err := yadisk.New(&yadisk.Config{
		OAuthToken: m.tcfg("token"),
		SessionID:  m.tcfg("session_id"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialYaTelemost(ctx context.Context) (net.Conn, error) {
	tr, err := yatelemost.New(&yatelemost.Config{
		SessionID:     m.tcfg("session_id"),
		ConferenceURL: m.tcfg("conference_url"),
		ICEPolicy:     "relay",
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialOKWebRTC(ctx context.Context) (net.Conn, error) {
	tr, err := okwebrtc.New(&okwebrtc.Config{
		OKToken: m.tcfg("ok_token"),
		OKAppID: m.tcfg("ok_app_id"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}


