package vkwebrtc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

var _ = registerFactory()

func registerFactory() bool {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
	return true
}

var log = logger.Module("vkwebrtc")

var framePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, maxRTPPayload)
		return &b
	},
}

const (
	ModuleName    = "transport.vkwebrtc"
	ModuleVersion = "1.0.0"

	rtpPayloadTypeVP8 = 96
	rtpClockRate      = 90000
	fps               = 30
	maxRTPPayload     = 1200

	vp8Start byte = 0x10
	vp8Cont  byte = 0x00

	defaultNumTracks = 3

	signalingPath = "/signal"

	SignalingVK        = "vk"
	SignalingWebSocket = "websocket"
)

var frameInterval = time.Second / fps

type sigMsg struct {
	Type      string `json:"type"`
	SDP       string `json:"sdp,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

type ICEServerConfig struct {
	URLs       []string
	Username   string
	Credential string
}

type Config struct {
	ServerMode    bool
	NumTracks     int
	SignalingMode string
	ICEPolicy     string
	ICEServers    []ICEServerConfig

	VKToken   string
	VKGroupID int64
	VKPeerID  int64

	TURNSharedSecret string

	TLSCert string
	TLSKey  string

	BufferSize int
}

func DefaultConfig() *Config {
	return &Config{
		NumTracks:     defaultNumTracks,
		SignalingMode: SignalingVK,
		ICEPolicy:     "relay",
		ICEServers: []ICEServerConfig{
			{
				URLs:       []string{"stun:stun.vk.com:3478"},
				Username:   "",
				Credential: "",
			},
			{
				URLs:       []string{"turn:turn.vk.com:3478"},
				Username:   "",
				Credential: "",
			},
		},
		BufferSize: 65536,
	}
}

type trackWriter struct {
	track *webrtc.TrackLocalStaticRTP
	mu    sync.Mutex
	seq   uint16
	ts    uint32
	ssrc  uint32
}

func newTrackWriter(n int) (*trackWriter, error) {
	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video",
		fmt.Sprintf("whispera-vpn-%d", n),
	)
	if err != nil {
		return nil, err
	}
	return &trackWriter{
		track: track,
		ssrc:  rand.Uint32(),
		ts:    rand.Uint32(),
	}, nil
}

func (w *trackWriter) sendFrame(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.ts += rtpClockRate / fps
	ts := w.ts
	total := uint16(len(data))
	offset := 0
	first := true

	for {
		var payload []byte
		var end int

		bp := framePool.Get().(*[]byte)
		if first {
			avail := maxRTPPayload - 3
			if avail > len(data)-offset {
				avail = len(data) - offset
			}
			end = offset + avail
			payload = (*bp)[:3+avail]
			payload[0] = vp8Start
			binary.BigEndian.PutUint16(payload[1:3], total)
			copy(payload[3:], data[offset:end])
			first = false
		} else {
			avail := maxRTPPayload - 1
			if avail > len(data)-offset {
				avail = len(data) - offset
			}
			end = offset + avail
			payload = (*bp)[:1+avail]
			payload[0] = vp8Cont
			copy(payload[1:], data[offset:end])
		}

		err := w.track.WriteRTP(&rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    rtpPayloadTypeVP8,
				SequenceNumber: w.seq,
				Timestamp:      ts,
				SSRC:           w.ssrc,
				Marker:         end >= len(data),
			},
			Payload: payload,
		})
		*bp = (*bp)[:cap(*bp)]
		framePool.Put(bp)
		if err != nil {
			return err
		}
		w.seq++
		offset = end
		if offset >= len(data) {
			break
		}
	}
	return nil
}

func (w *trackWriter) sendFiller() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.ts += rtpClockRate / fps
	_ = w.track.WriteRTP(&rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    rtpPayloadTypeVP8,
			SequenceNumber: w.seq,
			Timestamp:      w.ts,
			SSRC:           w.ssrc,
			Marker:         true,
		},
		Payload: []byte{vp8Start, 0x00, 0x00},
	})
	w.seq++
}

type Transport struct {
	*base.Module
	config     *Config
	writers    []*trackWriter
	client     *http.Client
	vkCallID   string

	api            *webrtc.API
	peerConnection *webrtc.PeerConnection

	lastDataSentNs int64

	dataIn  chan []byte
	dataOut chan []byte

	sigMu   sync.Mutex
	sigConn *websocket.Conn
	httpSrv *http.Server

	tracksReceived int32
	readyOnce      sync.Once
	ready          chan struct{}

	stopOnce  sync.Once
	stopChan  chan struct{}
	vkSigOnce sync.Once
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.NumTracks <= 0 {
		cfg.NumTracks = defaultNumTracks
	}

	writers := make([]*trackWriter, cfg.NumTracks)
	for i := range writers {
		w, err := newTrackWriter(i)
		if err != nil {
			return nil, fmt.Errorf("new track writer %d: %w", i, err)
		}
		writers[i] = w
	}

	return &Transport{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		config:   cfg,
		writers:  writers,
		client:   &http.Client{Timeout: 30 * time.Second},
		dataIn:   make(chan []byte, 1024),
		dataOut:  make(chan []byte, 1024),
		ready:    make(chan struct{}),
		stopChan: make(chan struct{}),
	}, nil
}

func (t *Transport) tryFetchTURNCredentials() {
	session, err := StartVKCall(t.client, t.config.VKToken, t.config.VKGroupID)
	if err != nil {
		log.Printf("TURN creds: calls.start failed: %v", err)
		t.tryHMACFallback()
		return
	}
	t.vkCallID = session.CallID
	log.Printf("VK call session %s, join_link: %s", session.CallID, session.JoinLink)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	servers, err := FetchICEServersFromVK(ctx, t.config.VKToken, session.JoinLink)
	if err != nil {
		log.Printf("TURN creds: VK call WS failed: %v — trying HMAC fallback", err)
		t.tryHMACFallback()
		return
	}

	t.mergeICEServers(servers)
	log.Printf("TURN creds: fetched from VK call WS (%d servers)", len(servers))
}

func (t *Transport) tryHMACFallback() {
	if t.config.TURNSharedSecret == "" {
		log.Printf("TURN creds: no TURNSharedSecret configured; relay-only ICE will likely fail")
		log.Printf("  → Capture VK iOS/Android call traffic with mitmproxy to find credentials")
		log.Printf("  → Or decompile VK APK and search for 'turn.vk.com' usage")
		return
	}

	user, pass := GenerateHMACTURNCredentials(
		t.config.TURNSharedSecret,
		fmt.Sprintf("whispera-%d", time.Now().Unix()),
		24*time.Hour,
	)
	log.Printf("TURN creds: generated via HMAC (username=%s)", user)
	t.mergeICEServers([]ICEServerConfig{{
		URLs:       []string{"turn:turn.vk.com:3478"},
		Username:   user,
		Credential: pass,
	}})
}

func (t *Transport) mergeICEServers(incoming []ICEServerConfig) {
	for _, inc := range incoming {
		merged := false
		for i, existing := range t.config.ICEServers {
			for _, eu := range existing.URLs {
				for _, iu := range inc.URLs {
					if eu == iu {
						t.config.ICEServers[i].Username = inc.Username
						t.config.ICEServers[i].Credential = inc.Credential
						merged = true
					}
				}
			}
		}
		if !merged {
			t.config.ICEServers = append(t.config.ICEServers, inc)
		}
	}
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		return fmt.Errorf("register codecs: %w", err)
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		return fmt.Errorf("register interceptors: %w", err)
	}

	t.api = webrtc.NewAPI(
		webrtc.WithMediaEngine(me),
		webrtc.WithInterceptorRegistry(ir),
		webrtc.WithSettingEngine(webrtc.SettingEngine{}),
	)

	if t.config.SignalingMode == SignalingVK && t.config.ICEPolicy == "relay" {
		t.tryFetchTURNCredentials()
	}

	iceServers := make([]webrtc.ICEServer, 0, len(t.config.ICEServers))
	for _, s := range t.config.ICEServers {
		srv := webrtc.ICEServer{URLs: s.URLs}
		if s.Username != "" {
			srv.Username = s.Username
			srv.Credential = s.Credential
			srv.CredentialType = webrtc.ICECredentialTypePassword
		}
		iceServers = append(iceServers, srv)
	}

	icePolicy := webrtc.ICETransportPolicyAll
	if t.config.ICEPolicy == "relay" {
		icePolicy = webrtc.ICETransportPolicyRelay
		log.Printf("ICE policy: relay-only (all traffic through TURN)")
	}

	pc, err := t.api.NewPeerConnection(webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: icePolicy,
	})
	if err != nil {
		return fmt.Errorf("new peer connection: %w", err)
	}
	t.peerConnection = pc

	for _, w := range t.writers {
		if _, err := pc.AddTransceiverFromTrack(w.track, webrtc.RTPTransceiverInit{
			Direction: webrtc.RTPTransceiverDirectionSendrecv,
		}); err != nil {
			return fmt.Errorf("add transceiver for %s: %w", w.track.StreamID(), err)
		}
	}

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("ICE state: %s", state.String())
		if state == webrtc.ICEConnectionStateConnected {
			go t.videoSendLoop()
		}
	})

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		raw, _ := json.Marshal(c.ToJSON())
		t.dispatchSignal(sigMsg{Type: "ice", Candidate: string(raw)})
	})

	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if track.Kind() != webrtc.RTPCodecTypeVideo {
			return
		}
		n := atomic.AddInt32(&t.tracksReceived, 1)
		log.Printf("Remote VP8 track %d/%d SSRC=%d", n, len(t.writers), track.SSRC())
		go t.receiveTrack(track)
		if n >= int32(len(t.writers)) {
			t.readyOnce.Do(func() { close(t.ready) })
		}
	})

	t.SetHealthy(true, "VK video transport started")
	log.Printf("VK video transport: %d tracks, signaling=%s, ICE=%s",
		len(t.writers), t.config.SignalingMode, t.config.ICEPolicy)
	return nil
}


func (t *Transport) dispatchSignal(msg sigMsg) {
	switch t.config.SignalingMode {
	case SignalingVK:
		t.vkSendSignal(msg)
	default:
		t.wsSendSignal(msg)
	}
}

func (t *Transport) handleSignalMsg(msg sigMsg) {
	switch msg.Type {
	case "offer":
		if !t.config.ServerMode {
			return
		}
		var offer webrtc.SessionDescription
		if err := json.Unmarshal([]byte(msg.SDP), &offer); err != nil {
			log.Printf("bad offer SDP: %v", err)
			return
		}
		if err := t.peerConnection.SetRemoteDescription(offer); err != nil {
			log.Printf("set remote desc: %v", err)
			return
		}
		answer, err := t.peerConnection.CreateAnswer(nil)
		if err != nil {
			log.Printf("create answer: %v", err)
			return
		}
		t.peerConnection.SetLocalDescription(answer)
		answerBytes, _ := json.Marshal(answer)
		t.dispatchSignal(sigMsg{Type: "answer", SDP: string(answerBytes)})

	case "answer":
		if t.config.ServerMode {
			return
		}
		var answer webrtc.SessionDescription
		json.Unmarshal([]byte(msg.SDP), &answer)
		t.peerConnection.SetRemoteDescription(answer)

	case "ice":
		var candidate webrtc.ICECandidateInit
		json.Unmarshal([]byte(msg.Candidate), &candidate)
		t.peerConnection.AddICECandidate(candidate)
	}
}


func (t *Transport) startVKSignaling() {
	t.vkSigOnce.Do(func() { go t.vkSignalingLoop() })
}

func (t *Transport) Listen(_ string) error {
	if t.config.SignalingMode == SignalingVK {
		t.startVKSignaling()
		return nil
	}
	return t.wsListen()
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	switch t.config.SignalingMode {
	case SignalingVK:
		t.startVKSignaling()
		offer, err := t.peerConnection.CreateOffer(nil)
		if err != nil {
			return nil, fmt.Errorf("create offer: %w", err)
		}
		if err = t.peerConnection.SetLocalDescription(offer); err != nil {
			return nil, fmt.Errorf("set local description: %w", err)
		}
		offerBytes, _ := json.Marshal(offer)
		t.vkSendSignal(sigMsg{Type: "offer", SDP: string(offerBytes)})
	default:
		ws, _, err := websocket.Dial(ctx, addr, nil)
		if err != nil {
			return nil, fmt.Errorf("signaling dial %s: %w", addr, err)
		}
		sigCtx, sigCancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-t.stopChan:
			case <-sigCtx.Done():
			}
			sigCancel()
		}()
		go t.wsClientLoop(sigCtx, sigCancel, ws)
	}

	select {
	case <-t.ready:
		return &vkWebRTCConn{transport: t}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.stopChan:
		return nil, io.ErrClosedPipe
	}
}

func (t *Transport) Accept() (net.Conn, error) {
	if t.config.SignalingMode == SignalingVK {
		t.startVKSignaling()
	}
	select {
	case <-t.ready:
		return &vkWebRTCConn{transport: t}, nil
	case <-t.stopChan:
		return nil, io.ErrClosedPipe
	}
}

func (t *Transport) vkSignalingLoop() {
	server, key, ts := t.vkGetLPServer()

	for {
		select {
		case <-t.stopChan:
			return
		default:
			t.vkPollLP(server, key, &ts)
		}
	}
}

func (t *Transport) vkGetLPServer() (string, string, int64) {
	u := fmt.Sprintf(
		"https://api.vk.com/method/groups.getLongPollServer?group_id=%d&access_token=%s&v=5.199",
		t.config.VKGroupID, t.config.VKToken)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		log.Printf("getLPServer: %v", err)
		time.Sleep(5 * time.Second)
		return "", "", 0
	}
	resp, err := t.client.Do(req)
	if err != nil {
		log.Printf("getLPServer: %v", err)
		time.Sleep(5 * time.Second)
		return "", "", 0
	}
	defer resp.Body.Close()

	var result struct {
		Response struct {
			Server string `json:"server"`
			Key    string `json:"key"`
			TS     string `json:"ts"`
		} `json:"response"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	var ts int64
	fmt.Sscanf(result.Response.TS, "%d", &ts)
	return result.Response.Server, result.Response.Key, ts
}

func (t *Transport) vkPollLP(server, key string, ts *int64) {
	if server == "" {
		time.Sleep(time.Second)
		return
	}

	u := fmt.Sprintf("%s?act=a_check&key=%s&ts=%d&wait=25", server, key, *ts)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		time.Sleep(time.Second)
		return
	}
	resp, err := t.client.Do(req)
	if err != nil {
		time.Sleep(time.Second)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	var raw map[string]interface{}
	json.Unmarshal(bodyBytes, &raw)
	if val, ok := raw["ts"]; ok {
		switch v := val.(type) {
		case float64:
			*ts = int64(v)
		case string:
			fmt.Sscanf(v, "%d", ts)
		}
	} else {
		return
	}

	var result struct {
		Updates []struct {
			Type   string `json:"type"`
			Object struct {
				Message struct {
					Text   string `json:"text"`
					PeerID int64  `json:"peer_id"`
				} `json:"message"`
			} `json:"object"`
		} `json:"updates"`
	}
	json.Unmarshal(bodyBytes, &result)

	for _, upd := range result.Updates {
		if upd.Type == "message_new" && upd.Object.Message.PeerID == t.config.VKPeerID {
			text := upd.Object.Message.Text
			if len(text) > 7 && text[:7] == "WEBRTC:" {
				var msg sigMsg
				if err := json.Unmarshal([]byte(text[7:]), &msg); err == nil {
					t.handleSignalMsg(msg)
				}
			}
		}
	}
}

func (t *Transport) vkSendSignal(msg sigMsg) {
	data, _ := json.Marshal(msg)
	text := "WEBRTC:" + string(data)

	apiURL := fmt.Sprintf(
		"https://api.vk.com/method/messages.send?peer_id=%d&message=%s&random_id=%d&access_token=%s&v=5.199",
		t.config.VKPeerID, url.QueryEscape(text), time.Now().UnixNano(), t.config.VKToken)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
	if err != nil {
		log.Printf("vkSendSignal: %v", err)
		return
	}
	resp, err := t.client.Do(req)
	if err != nil {
		log.Printf("vkSendSignal: %v", err)
		return
	}
	resp.Body.Close()
}


func (t *Transport) wsListen() error {
	mux := http.NewServeMux()
	mux.HandleFunc(signalingPath, func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			log.Printf("ws accept: %v", err)
			return
		}
		t.wsServerLoop(ws)
	})
	srv := &http.Server{Addr: "", Handler: mux}
	t.httpSrv = srv
	return nil
}

func (t *Transport) wsServerLoop(ws *websocket.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer ws.Close(websocket.StatusNormalClosure, "")

	t.sigMu.Lock()
	t.sigConn = ws
	t.sigMu.Unlock()
	defer func() {
		t.sigMu.Lock()
		if t.sigConn == ws {
			t.sigConn = nil
		}
		t.sigMu.Unlock()
	}()

	for {
		var msg sigMsg
		if err := wsjson.Read(ctx, ws, &msg); err != nil {
			return
		}
		t.handleSignalMsg(msg)
	}
}

func (t *Transport) wsClientLoop(ctx context.Context, cancel context.CancelFunc, ws *websocket.Conn) {
	defer cancel()
	defer ws.Close(websocket.StatusNormalClosure, "")

	t.sigMu.Lock()
	t.sigConn = ws
	t.sigMu.Unlock()
	defer func() {
		t.sigMu.Lock()
		if t.sigConn == ws {
			t.sigConn = nil
		}
		t.sigMu.Unlock()
	}()

	offer, err := t.peerConnection.CreateOffer(nil)
	if err != nil {
		log.Printf("create offer: %v", err)
		return
	}
	t.peerConnection.SetLocalDescription(offer)
	offerBytes, _ := json.Marshal(offer)
	wsjson.Write(ctx, ws, sigMsg{Type: "offer", SDP: string(offerBytes)})

	for {
		var msg sigMsg
		if err := wsjson.Read(ctx, ws, &msg); err != nil {
			return
		}
		t.handleSignalMsg(msg)
	}
}

func (t *Transport) wsSendSignal(msg sigMsg) {
	t.sigMu.Lock()
	conn := t.sigConn
	t.sigMu.Unlock()
	if conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsjson.Write(ctx, conn, msg)
}


func (t *Transport) videoSendLoop() {
	for _, w := range t.writers {
		w := w
		go func() {
			for {
				select {
				case pkt := <-t.dataOut:
					atomic.StoreInt64(&t.lastDataSentNs, time.Now().UnixNano())
					if err := w.sendFrame(pkt); err != nil {
						log.Printf("sendFrame: %v", err)
					}
				case <-t.stopChan:
					return
				}
			}
		}()
	}

	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopChan:
			return
		case <-ticker.C:
			idle := time.Since(time.Unix(0, atomic.LoadInt64(&t.lastDataSentNs)))
			if idle >= frameInterval {
				for _, w := range t.writers {
					w.sendFiller()
				}
			}
		}
	}
}

func (t *Transport) receiveTrack(track *webrtc.TrackRemote) {
	var frameBuf []byte
	frameWant := -1

	for {
		select {
		case <-t.stopChan:
			return
		default:
		}

		pkt, _, err := track.ReadRTP()
		if err != nil {
			if err != io.EOF {
				log.Printf("receiveTrack: %v", err)
			}
			return
		}

		p := pkt.Payload
		if len(p) == 0 {
			continue
		}
		desc := p[0]
		p = p[1:]

		if desc&0x10 != 0 {
			if len(p) < 2 {
				continue
			}
			frameWant = int(binary.BigEndian.Uint16(p[:2]))
			p = p[2:]
			frameBuf = frameBuf[:0]
		}
		if frameWant > 0 {
			frameBuf = append(frameBuf, p...)
		}
		if pkt.Header.Marker {
			if frameWant > 0 && len(frameBuf) == frameWant {
				out := make([]byte, frameWant)
				copy(out, frameBuf)
				select {
				case t.dataIn <- out:
				case <-t.stopChan:
					return
				default:
					log.Printf("dataIn full, dropping frame")
				}
			}
			frameBuf = frameBuf[:0]
			frameWant = -1
		}
	}
}


func (t *Transport) Stop() error {
	t.stopOnce.Do(func() { close(t.stopChan) })
	if t.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		t.httpSrv.Shutdown(ctx)
	}
	if t.peerConnection != nil {
		t.peerConnection.Close()
	}
	if t.vkCallID != "" {
		ForceFinishCall(t.client, t.config.VKToken, t.vkCallID)
	}
	return t.Module.Stop()
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportVKWebRTC }
func (t *Transport) Close() error                   { return t.Stop() }


type vkWebRTCConn struct {
	transport *Transport
	mu        sync.Mutex
	buf       bytes.Buffer
}

func (c *vkWebRTCConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.buf.Len() > 0 {
		n, _ := c.buf.Read(b)
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	select {
	case data, ok := <-c.transport.dataIn:
		if !ok {
			return 0, io.EOF
		}
		c.mu.Lock()
		c.buf.Write(data)
		n, _ := c.buf.Read(b)
		c.mu.Unlock()
		return n, nil
	case <-c.transport.stopChan:
		return 0, io.EOF
	}
}

func (c *vkWebRTCConn) Write(b []byte) (int, error) {
	pkt := make([]byte, len(b))
	copy(pkt, b)
	select {
	case c.transport.dataOut <- pkt:
		return len(b), nil
	case <-c.transport.stopChan:
		return 0, io.ErrClosedPipe
	}
}

func (c *vkWebRTCConn) Close() error                       { return nil }
func (c *vkWebRTCConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *vkWebRTCConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *vkWebRTCConn) SetDeadline(_ time.Time) error      { return nil }
func (c *vkWebRTCConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *vkWebRTCConn) SetWriteDeadline(_ time.Time) error { return nil }


func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
