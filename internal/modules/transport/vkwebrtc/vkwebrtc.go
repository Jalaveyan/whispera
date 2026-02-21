package vkwebrtc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("vkwebrtc")

const (
	ModuleName    = "transport.vkwebrtc"
	ModuleVersion = "1.0.0"
)

type Config struct {
	Token      string
	GroupID    int64
	PeerID     int64
	ServerMode bool
	ICEServers []string
	BufferSize int
}

func DefaultConfig() *Config {
	return &Config{
		ICEServers: []string{
			"stun:stun.vk.com:3478",
			"turn:turn.vk.com:3478",
		},
		BufferSize: 65536,
	}
}

type Transport struct {
	*base.Module
	config *Config
	client *http.Client

	api            *webrtc.API
	peerConnection *webrtc.PeerConnection
	dataChannel    *webrtc.DataChannel

	dataIn  chan []byte
	dataOut chan []byte

	connected bool
	ready     chan struct{}

	stopChan chan struct{}
	mu       sync.RWMutex
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	t := &Transport{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		config:   cfg,
		client:   &http.Client{Timeout: 30 * time.Second},
		dataIn:   make(chan []byte, 10000),
		dataOut:  make(chan []byte, 10000),
		ready:    make(chan struct{}),
		stopChan: make(chan struct{}),
	}

	return t, nil
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	settingEngine := webrtc.SettingEngine{}
	t.api = webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	iceServers := []webrtc.ICEServer{}
	if len(t.config.ICEServers) > 0 {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs: t.config.ICEServers,
		})
	}

	config := webrtc.Configuration{
		ICEServers: iceServers,
	}

	pc, err := t.api.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %w", err)
	}
	t.peerConnection = pc

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("ICE Connection State has changed: %s", state.String())
	})

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		cancel := c.ToJSON()
		candidateStr, _ := json.Marshal(cancel)
		t.sendSignaling("ice", "", string(candidateStr))
	})

	if t.config.ServerMode {
		pc.OnDataChannel(func(d *webrtc.DataChannel) {
			log.Printf("New DataChannel %s %d", d.Label(), d.ID())
			t.setupDataChannel(d)
		})
	} else {
		ordered := true

		dcConfig := &webrtc.DataChannelInit{
			Ordered: &ordered,
		}

		dc, err := pc.CreateDataChannel("whispera-vpn", dcConfig)
		if err != nil {
			return fmt.Errorf("failed to create data channel: %w", err)
		}
		t.setupDataChannel(dc)
	}

	go t.signalingLoop()

	if !t.config.ServerMode {
		offer, err := pc.CreateOffer(nil)
		if err != nil {
			return fmt.Errorf("failed to create offer: %w", err)
		}

		if err = pc.SetLocalDescription(offer); err != nil {
			return fmt.Errorf("failed to set local description: %w", err)
		}

		offerByte, _ := json.Marshal(offer)
		t.sendSignaling("offer", string(offerByte), "")
	}

	t.SetHealthy(true, "VK WebRTC transport started")
	log.Printf("VK WebRTC transport started (mode: %v)", t.config.ServerMode)

	return nil
}

func (t *Transport) setupDataChannel(d *webrtc.DataChannel) {
	t.dataChannel = d

	d.OnOpen(func() {
		log.Printf("Data channel '%s'-'%d' open", d.Label(), d.ID())
		t.connected = true
		close(t.ready)
	})

	d.OnMessage(func(msg webrtc.DataChannelMessage) {
		select {
		case t.dataIn <- msg.Data:
		default:
			log.Printf("Input buffer full, dropping packet")
		}
	})

	d.OnClose(func() {
		log.Printf("Data channel closed")
		t.connected = false
	})
}

func (t *Transport) signalingLoop() {
	lpServer, lpKey, lpTS := t.getLongpollServer()

	for {
		select {
		case <-t.stopChan:
			return
		default:
			t.pollSignaling(lpServer, lpKey, &lpTS)
		}
	}
}

func (t *Transport) getLongpollServer() (string, string, int64) {
	url := fmt.Sprintf("https://api.vk.com/method/groups.getLongPollServer?group_id=%d&access_token=%s&v=5.199",
		t.config.GroupID, t.config.Token)

	resp, err := t.client.Get(url)
	if err != nil {
		log.Printf("Failed to get LP server: %v", err)
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

func (t *Transport) pollSignaling(server, key string, ts *int64) {
	if server == "" {
		time.Sleep(time.Second)
		return
	}

	url := fmt.Sprintf("%s?act=a_check&key=%s&ts=%d&wait=25", server, key, *ts)
	resp, err := t.client.Get(url)
	if err != nil {
		time.Sleep(time.Second)
		return
	}
	defer resp.Body.Close()

	var result struct {
		TS string `json:"ts"`
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

	var raw map[string]interface{}
	bodyBytes, _ := io.ReadAll(resp.Body)
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

	json.Unmarshal(bodyBytes, &result)

	for _, update := range result.Updates {
		if update.Type == "message_new" && update.Object.Message.PeerID == t.config.PeerID {
			text := update.Object.Message.Text
			if len(text) > 7 && text[:7] == "WEBRTC:" {
				t.handleSignalingMessage(text[7:])
			}
		}
	}
}

func (t *Transport) handleSignalingMessage(msg string) {
	var signal struct {
		Type      string `json:"type"`
		SDP       string `json:"sdp,omitempty"`
		Candidate string `json:"candidate,omitempty"`
	}

	if err := json.Unmarshal([]byte(msg), &signal); err != nil {
		return
	}

	switch signal.Type {
	case "offer":
		if !t.config.ServerMode {
			return
		}
		var offer webrtc.SessionDescription
		json.Unmarshal([]byte(signal.SDP), &offer)
		t.peerConnection.SetRemoteDescription(offer)

		answer, err := t.peerConnection.CreateAnswer(nil)
		if err == nil {
			t.peerConnection.SetLocalDescription(answer)
			answerByte, _ := json.Marshal(answer)
			t.sendSignaling("answer", string(answerByte), "")
		}

	case "answer":
		if t.config.ServerMode {
			return
		}
		var answer webrtc.SessionDescription
		json.Unmarshal([]byte(signal.SDP), &answer)
		t.peerConnection.SetRemoteDescription(answer)

	case "ice":
		var candidate webrtc.ICECandidateInit
		json.Unmarshal([]byte(signal.Candidate), &candidate)
		t.peerConnection.AddICECandidate(candidate)
	}
}

func (t *Transport) sendSignaling(msgType, sdp, candidate string) {
	signal := map[string]string{
		"type": msgType,
	}
	if sdp != "" {
		signal["sdp"] = sdp
	}
	if candidate != "" {
		signal["candidate"] = candidate
	}

	data, _ := json.Marshal(signal)
	msg := "WEBRTC:" + string(data)

	apiURL := fmt.Sprintf("https://api.vk.com/method/messages.send?peer_id=%d&message=%s&random_id=%d&access_token=%s&v=5.199",
		t.config.PeerID, url.QueryEscape(msg), time.Now().UnixNano(), t.config.Token)

	resp, err := t.client.Get(apiURL)
	if err != nil {
		log.Printf("sendSignaling failed: %v", err)
		return
	}
	resp.Body.Close()
}

func (t *Transport) Stop() error {
	close(t.stopChan)
	if t.peerConnection != nil {
		t.peerConnection.Close()
	}
	return t.Module.Stop()
}

func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportWebSocket
}

func (t *Transport) Listen(addr string) error {
	return nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	<-t.ready
	return &vkWebRTCConn{transport: t}, nil
}

func (t *Transport) Accept() (net.Conn, error) {
	<-t.ready
	return &vkWebRTCConn{transport: t}, nil
}

func (t *Transport) Close() error {
	return t.Stop()
}

type vkWebRTCConn struct {
	transport *Transport
}

func (c *vkWebRTCConn) Read(b []byte) (int, error) {
	select {
	case data, ok := <-c.transport.dataIn:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		return n, nil
	case <-c.transport.stopChan:
		return 0, io.EOF
	}
}

func (c *vkWebRTCConn) Write(b []byte) (int, error) {
	if c.transport.dataChannel == nil {
		return 0, io.ErrClosedPipe
	}
	err := c.transport.dataChannel.Send(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *vkWebRTCConn) Close() error                       { return nil }
func (c *vkWebRTCConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *vkWebRTCConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *vkWebRTCConn) SetDeadline(t time.Time) error      { return nil }
func (c *vkWebRTCConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *vkWebRTCConn) SetWriteDeadline(t time.Time) error { return nil }

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
