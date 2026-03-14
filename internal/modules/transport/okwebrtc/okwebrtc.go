package okwebrtc


import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("okwebrtc")

const (
	ModuleName    = "transport.okwebrtc"
	ModuleVersion = "1.0.0"

	okAPIBase = "https://api.ok.ru/fb.do"
	okCDNBase = "https://calls.okcdn.ru/fb.do"
	okAppKey  = "CGMMEJLGDIHBABABA"

	payloadTypeVP8 = 96
	clockRate      = 90000
	maxPayload     = 1200
	fps            = 30

	vp8Start byte = 0x10
	vp8Cont  byte = 0x00
)

type Config struct {
	ServerMode bool

	OKToken string

	OKAppID string

	OKAppSecretKey string

	SignalingMode string

	SignalingURL string

	ICEPolicy string

	NumTracks int

	TLSCert, TLSKey string

	BufferSize int
}

func DefaultConfig() *Config {
	return &Config{
		SignalingMode: "websocket",
		ICEPolicy:     "relay",
		NumTracks:     3,
		BufferSize:    32 * 1024,
	}
}

type ICEServerConfig struct {
	URLs       []string
	Username   string
	Credential string
}

type okcdnTurnServer struct {
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	URLs       []string `json:"urls"`
}

type trackWriter struct {
	track *webrtc.TrackLocalStaticRTP
	mu    sync.Mutex
	seq   uint16
	ts    uint32
	ssrc  uint32
}

type Transport struct {
	*base.Module
	config  *Config
	client  *http.Client
	writers []*trackWriter

	pc  *webrtc.PeerConnection
	api *webrtc.API

	sigWS   *websocket.Conn
	httpSrv *http.Server
	sigMu   sync.Mutex

	tracksReceived int32
	dataIn, dataOut chan []byte
	lastSentNs      int64

	ready     chan struct{}
	readyOnce sync.Once
	stopCh    chan struct{}
	stopOnce  sync.Once
}

type sigMsg struct {
	Type      string `json:"type"`
	SDP       string `json:"sdp,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	c, ok := cfg.(*Config)
	if !ok {
		c = DefaultConfig()
	}
	return New(c)
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.NumTracks == 0 {
		cfg.NumTracks = 3
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 32 * 1024
	}
	return &Transport{
		Module:  base.NewModule(ModuleName, ModuleVersion, nil),
		config:  cfg,
		client:  &http.Client{Timeout: 15 * time.Second},
		dataIn:  make(chan []byte, 256),
		dataOut: make(chan []byte, 256),
		ready:   make(chan struct{}),
		stopCh:  make(chan struct{}),
	}, nil
}

func (t *Transport) Start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Printf("okwebrtc: fetching TURN credentials from OK.ru...")
	iceServers, err := t.fetchTURNCredentials(ctx)
	if err != nil {
		log.Printf("okwebrtc: TURN fetch failed: %v — using no credentials", err)
		iceServers = nil
	}

	if err := t.buildPeerConnection(iceServers); err != nil {
		return fmt.Errorf("build peer connection: %w", err)
	}

	if t.config.ServerMode {
		go t.startWSServer()
	} else {
		go t.connectWSClient()
	}

	numTracks := t.config.NumTracks
	for i := 0; i < numTracks; i++ {
		go t.videoSendLoop(i)
	}

	return nil
}

func (t *Transport) Stop() error {
	t.stopOnce.Do(func() {
		close(t.stopCh)
		t.sigMu.Lock()
		if t.sigWS != nil {
			t.sigWS.Close(websocket.StatusGoingAway, "stopped")
		}
		t.sigMu.Unlock()
		if t.httpSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			t.httpSrv.Shutdown(ctx)
		}
		if t.pc != nil {
			t.pc.Close()
		}
	})
	return nil
}

func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	select {
	case <-t.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.stopCh:
		return nil, fmt.Errorf("okwebrtc: stopped")
	}
	return &okConn{t: t}, nil
}

func (t *Transport) Accept() (net.Conn, error) {
	select {
	case <-t.ready:
	case <-t.stopCh:
		return nil, fmt.Errorf("okwebrtc: stopped")
	}
	return &okConn{t: t}, nil
}

func (t *Transport) fetchTURNCredentials(ctx context.Context) ([]ICEServerConfig, error) {
	tok1, err := okGetAnonToken(ctx, t.client, "", "")
	if err != nil {
		return nil, fmt.Errorf("step1: %w", err)
	}
	payload, err := okGetCallsPayload(ctx, t.client, tok1)
	if err != nil {
		return nil, fmt.Errorf("step2: %w", err)
	}
	tok3, err := okGetAnonToken(ctx, t.client, payload, "messages")
	if err != nil {
		return nil, fmt.Errorf("step3: %w", err)
	}

	joinLink, err := t.createOKConference(ctx, tok3)
	if err != nil {
		return nil, fmt.Errorf("create conference: %w", err)
	}
	log.Printf("okwebrtc: OK.ru conference join_link: %s", joinLink)

	callTok, err := okGetAnonymousCallToken(ctx, t.client, tok3, joinLink)
	if err != nil {
		return nil, fmt.Errorf("step4b: %w", err)
	}

	sessionKey, err := okcdnAnonLogin(ctx, t.client)
	if err != nil {
		return nil, fmt.Errorf("step5: %w", err)
	}

	hash := extractHash(joinLink)
	servers, err := okcdnJoin(ctx, t.client, sessionKey, callTok, hash)
	if err != nil {
		return nil, fmt.Errorf("step6: %w", err)
	}

	log.Printf("okwebrtc: got %d TURN server(s)", len(servers))
	return servers, nil
}

func (t *Transport) createOKConference(ctx context.Context, anonToken string) (string, error) {
	params := url.Values{
		"method":          {"vchat.createConference"},
		"format":          {"JSON"},
		"application_key": {okAppKey},
		"access_token":    {anonToken},
	}
	if t.config.OKToken != "" {
		params.Set("access_token", t.config.OKToken)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", okcdnBase,
		bytes.NewBufferString(params.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		ConferenceLink string `json:"conferenceLink"`
		JoinLink       string `json:"join_link"`
		ErrorCode      int    `json:"error_code"`
		ErrorMsg       string `json:"error_message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w (body: %s)", err, body)
	}
	if result.ErrorCode != 0 {
		return "", fmt.Errorf("okcdn error %d: %s", result.ErrorCode, result.ErrorMsg)
	}

	link := result.JoinLink
	if link == "" {
		link = result.ConferenceLink
	}
	if link == "" {
		return "", fmt.Errorf("no join link in response (body: %s)", body)
	}
	return link, nil
}

func (t *Transport) buildPeerConnection(iceServers []ICEServerConfig) error {
	me := &webrtc.MediaEngine{}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType: webrtc.MimeTypeVP8, ClockRate: clockRate,
		},
		PayloadType: payloadTypeVP8,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return err
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		return err
	}
	t.api = webrtc.NewAPI(
		webrtc.WithMediaEngine(me),
		webrtc.WithInterceptorRegistry(ir),
	)

	policy := webrtc.ICETransportPolicyAll
	if t.config.ICEPolicy == "relay" {
		policy = webrtc.ICETransportPolicyRelay
	}
	var servers []webrtc.ICEServer
	for _, s := range iceServers {
		servers = append(servers, webrtc.ICEServer{
			URLs:       s.URLs,
			Username:   s.Username,
			Credential: s.Credential,
		})
	}

	pc, err := t.api.NewPeerConnection(webrtc.Configuration{
		ICEServers:         servers,
		ICETransportPolicy: policy,
	})
	if err != nil {
		return err
	}
	t.pc = pc

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		t.sigMu.Lock()
		ws := t.sigWS
		t.sigMu.Unlock()
		if ws != nil {
			wsjson.Write(context.Background(), ws, sigMsg{
				Type:      "ice",
				Candidate: c.ToJSON().Candidate,
			})
		}
	})

	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		go t.readTrack(track)
	})

	numTracks := t.config.NumTracks
	t.writers = make([]*trackWriter, numTracks)
	for i := 0; i < numTracks; i++ {
		localTrack, err := webrtc.NewTrackLocalStaticRTP(
			webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
			fmt.Sprintf("video%d", i),
			fmt.Sprintf("stream%d", i),
		)
		if err != nil {
			return err
		}
		if _, err := pc.AddTransceiverFromTrack(localTrack, webrtc.RTPTransceiverInit{
			Direction: webrtc.RTPTransceiverDirectionSendrecv,
		}); err != nil {
			return err
		}
		t.writers[i] = &trackWriter{
			track: localTrack,
			ssrc:  uint32(0x1234 + i),
		}
	}
	return nil
}

func (t *Transport) readTrack(track *webrtc.TrackRemote) {
	n := atomic.AddInt32(&t.tracksReceived, 1)
	if n == int32(t.config.NumTracks) {
		t.readyOnce.Do(func() { close(t.ready) })
	}

	var frame []byte
	for {
		pkt := &rtp.Packet{}
		rawPkt := make([]byte, 1500)
		size, _, err := track.Read(rawPkt)
		if err != nil {
			return
		}
		if err := pkt.Unmarshal(rawPkt[:size]); err != nil {
			continue
		}
		if len(pkt.Payload) < 3 {
			continue
		}
		if pkt.Payload[0] == vp8Start {
			dataLen := int(pkt.Payload[1])<<8 | int(pkt.Payload[2])
			frame = make([]byte, 0, dataLen)
			frame = append(frame, pkt.Payload[3:]...)
		} else {
			frame = append(frame, pkt.Payload[1:]...)
		}
		if pkt.Marker && len(frame) > 0 {
			cp := make([]byte, len(frame))
			copy(cp, frame)
			select {
			case t.dataIn <- cp:
			default:
			}
			frame = nil
		}
	}
}

func (t *Transport) videoSendLoop(i int) {
	w := t.writers[i]
	ticker := time.NewTicker(time.Second / fps)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case data := <-t.dataOut:
			atomic.StoreInt64(&t.lastSentNs, time.Now().UnixNano())
			w.sendFrame(data)
		case <-ticker.C:
			if time.Duration(time.Now().UnixNano()-atomic.LoadInt64(&t.lastSentNs)) >= time.Second/fps {
				w.sendFrame([]byte{0x00})
			}
		}
	}
}

func (w *trackWriter) sendFrame(data []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()

	ts := w.ts
	w.ts += clockRate / fps

	offset := 0
	for offset < len(data) {
		end := offset + maxPayload - 3
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		isLast := end == len(data)

		var payload []byte
		if offset == 0 {
			l := len(data)
			payload = append([]byte{vp8Start, byte(l >> 8), byte(l)}, chunk...)
		} else {
			payload = append([]byte{vp8Cont}, chunk...)
		}

		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    payloadTypeVP8,
				SequenceNumber: w.seq,
				Timestamp:      ts,
				SSRC:           w.ssrc,
				Marker:         isLast,
			},
			Payload: payload,
		}
		w.seq++
		raw, _ := pkt.Marshal()
		w.track.Write(raw)
		offset = end
	}
}

func (t *Transport) startWSServer() {
	addr := t.config.SignalingURL
	if addr == "" {
		addr = ":9443"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/signal", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		t.sigMu.Lock()
		t.sigWS = ws
		t.sigMu.Unlock()
		t.runSigLoop(context.Background(), ws, true)
	})
	t.httpSrv = &http.Server{Addr: addr, Handler: mux}
	if t.config.TLSCert != "" {
		t.httpSrv.ListenAndServeTLS(t.config.TLSCert, t.config.TLSKey)
	} else {
		t.httpSrv.ListenAndServe()
	}
}

func (t *Transport) connectWSClient() {
	ctx := context.Background()
	ws, _, err := websocket.Dial(ctx, t.config.SignalingURL, nil)
	if err != nil {
		log.Printf("okwebrtc: signaling connect error: %v", err)
		return
	}
	t.sigMu.Lock()
	t.sigWS = ws
	t.sigMu.Unlock()

	offer, err := t.pc.CreateOffer(nil)
	if err == nil {
		t.pc.SetLocalDescription(offer)
		wsjson.Write(ctx, ws, sigMsg{Type: "offer", SDP: offer.SDP})
	}
	t.runSigLoop(ctx, ws, false)
}

func (t *Transport) runSigLoop(ctx context.Context, ws *websocket.Conn, isServer bool) {
	for {
		var msg sigMsg
		if err := wsjson.Read(ctx, ws, &msg); err != nil {
			return
		}
		switch msg.Type {
		case "offer":
			if err := t.pc.SetRemoteDescription(webrtc.SessionDescription{
				Type: webrtc.SDPTypeOffer, SDP: msg.SDP,
			}); err != nil {
				continue
			}
			answer, _ := t.pc.CreateAnswer(nil)
			t.pc.SetLocalDescription(answer)
			wsjson.Write(ctx, ws, sigMsg{Type: "answer", SDP: answer.SDP})
		case "answer":
			t.pc.SetRemoteDescription(webrtc.SessionDescription{
				Type: webrtc.SDPTypeAnswer, SDP: msg.SDP,
			})
		case "ice":
			t.pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: msg.Candidate})
		}
	}
}

type okConn struct {
	t   *Transport
	buf []byte
	mu  sync.Mutex
}

func (c *okConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	select {
	case data := <-c.t.dataIn:
		n := copy(p, data)
		if n < len(data) {
			c.mu.Lock()
			c.buf = append(c.buf, data[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	case <-c.t.stopCh:
		return 0, fmt.Errorf("okwebrtc: closed")
	}
}

func (c *okConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case c.t.dataOut <- cp:
		return len(p), nil
	case <-c.t.stopCh:
		return 0, fmt.Errorf("okwebrtc: closed")
	}
}

func (c *okConn) Close() error                       { return c.t.Stop() }
func (c *okConn) SetDeadline(t time.Time) error      { return nil }
func (c *okConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *okConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *okConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *okConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }


const (
	vkAnonClientID     = "6287487"
	vkAnonClientSecret = "QbYic1K3lEV5kTGiqlq2"
	vkLoginEndpoint    = "https://login.vk.ru/?act=get_anonym_token"
	vkAPIBase          = "https://api.vk.ru/method"
	okcdnBase          = "https://calls.okcdn.ru/fb.do"
)

func okGetAnonToken(ctx context.Context, client *http.Client, payload, tokenType string) (string, error) {
	form := url.Values{
		"client_id":     {vkAnonClientID},
		"client_secret": {vkAnonClientSecret},
		"version":       {"1"},
		"app_id":        {vkAnonClientID},
	}
	if payload != "" {
		form.Set("payload", payload)
		form.Set("token_type", tokenType)
	} else {
		form.Set("scopes", "audio_anonymous,video_anonymous,photos_anonymous,profile_anonymous")
		form.Set("isApiOauthAnonymEnabled", "false")
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", vkLoginEndpoint,
		bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w (body: %s)", err, body)
	}
	if result.Data.AccessToken == "" {
		return "", fmt.Errorf("empty token (body: %s)", body)
	}
	return result.Data.AccessToken, nil
}

func okGetCallsPayload(ctx context.Context, client *http.Client, tok string) (string, error) {
	endpoint := vkAPIBase + "/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=" + vkAnonClientID
	form := url.Values{"access_token": {tok}}
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint,
		bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Response struct{ Payload string `json:"payload"` } `json:"response"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	return result.Response.Payload, nil
}

func okGetAnonymousCallToken(ctx context.Context, client *http.Client, tok, joinLink string) (string, error) {
	form := url.Values{
		"vk_join_link": {joinLink},
		"name":         {"Anonymous"},
		"access_token": {tok},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST",
		vkAPIBase+"/calls.getAnonymousToken?v=5.264",
		bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Response struct{ Token string `json:"token"` } `json:"response"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	return result.Response.Token, nil
}

func okcdnAnonLogin(ctx context.Context, client *http.Client) (string, error) {
	sessionData, _ := json.Marshal(map[string]interface{}{
		"version": 2, "device_id": fmt.Sprintf("ok-%d", time.Now().UnixNano()),
		"client_version": 1.1, "client_type": "SDK_JS",
	})
	form := url.Values{
		"session_data": {string(sessionData)}, "method": {"auth.anonymLogin"},
		"format": {"JSON"}, "application_key": {okAppKey},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", okcdnBase,
		bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		SessionKey string `json:"session_key"`
		ErrorCode  int    `json:"error_code"`
		ErrorMsg   string `json:"error_message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w (body: %s)", err, body)
	}
	if result.ErrorCode != 0 {
		return "", fmt.Errorf("okcdn error %d: %s", result.ErrorCode, result.ErrorMsg)
	}
	return result.SessionKey, nil
}

func okcdnJoin(ctx context.Context, client *http.Client, sessionKey, callToken, hash string) ([]ICEServerConfig, error) {
	form := url.Values{
		"joinLink": {hash}, "isVideo": {"false"}, "protocolVersion": {"5"},
		"anonymToken": {callToken}, "method": {"vchat.joinConversationByLink"},
		"format": {"JSON"}, "application_key": {okAppKey}, "session_key": {sessionKey},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", okcdnBase,
		bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		TurnServer *okcdnTurnServer `json:"turn_server"`
		ErrorCode  int              `json:"error_code"`
		ErrorMsg   string           `json:"error_message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse: %w (body: %s)", err, body)
	}
	if result.ErrorCode != 0 {
		return nil, fmt.Errorf("okcdn error %d: %s", result.ErrorCode, result.ErrorMsg)
	}
	if result.TurnServer == nil {
		return nil, fmt.Errorf("no turn_server (body: %s)", body)
	}
	return []ICEServerConfig{{
		URLs:       result.TurnServer.URLs,
		Username:   result.TurnServer.Username,
		Credential: result.TurnServer.Credential,
	}}, nil
}

func extractHash(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	for _, prefix := range []string{"/call/join/", "/calls/join/"} {
		if i := len(u.Path) - len(u.Path[len(prefix):]); i >= 0 {
			_ = i
		}
	}
	if idx := lastIndex(u.Path, "/"); idx >= 0 {
		return u.Path[idx+1:]
	}
	return link
}

func lastIndex(s, sub string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == sub[0] {
			return i
		}
	}
	return -1
}
