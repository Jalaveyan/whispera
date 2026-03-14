package vkbot

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("vkbot")

const (
	ModuleName    = "transport.vkbot"
	ModuleVersion = "1.0.0"

	vkAPIBase    = "https://api.vk.com/method"
	vkAPIVersion = "5.131"

	msgPrefix = "WRP:"
	maxChunk  = 2000

	communityPeerOffset = 2_000_000_000
)

type Config struct {
	GroupID int64

	GroupToken string

	UserToken string

	ServerMode bool
}

func (c *Config) Validate() error {
	if c.GroupID == 0 {
		return fmt.Errorf("vkbot: GroupID required")
	}
	if c.ServerMode && c.GroupToken == "" {
		return fmt.Errorf("vkbot: GroupToken required in server mode")
	}
	if !c.ServerMode && c.UserToken == "" {
		return fmt.Errorf("vkbot: UserToken required in client mode")
	}
	return nil
}

type Transport struct {
	*base.Module
	cfg      *Config
	hc       *http.Client
	stopChan chan struct{}
	accept   chan net.Conn
	stopped  atomic.Bool
}

func New(cfg *Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	t := &Transport{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		cfg:      cfg,
		hc:       &http.Client{Timeout: 35 * time.Second},
		stopChan: make(chan struct{}),
		accept:   make(chan net.Conn, 32),
	}
	return t, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportVKBot }
func (t *Transport) Listen(addr string) error        { return nil }

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}
	if t.cfg.ServerMode {
		go t.listenLoop()
	}
	t.SetHealthy(true, "vkbot transport running")
	return nil
}

func (t *Transport) Stop() error {
	if t.stopped.CompareAndSwap(false, true) {
		close(t.stopChan)
	}
	return t.Module.Stop()
}

func (t *Transport) Close() error { return t.Stop() }

func (t *Transport) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-t.accept:
		if !ok {
			return nil, io.EOF
		}
		return conn, nil
	case <-t.stopChan:
		return nil, io.EOF
	}
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	peerID := communityPeerOffset + t.cfg.GroupID
	conn := newBotConn(t, peerID)

	ctx2, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-t.stopChan:
			cancel()
		case <-ctx2.Done():
		}
	}()
	go conn.userPollLoop(ctx2, cancel)
	return conn, nil
}


func (t *Transport) listenLoop() {
	conns := make(map[int64]*botConn)
	server, key, ts := t.fetchGroupLPServer()

	for {
		select {
		case <-t.stopChan:
			return
		default:
		}

		events, newTS, err := t.pollGroup(server, key, ts)
		if err != nil {
			log.Warn("[vkbot] group LP error: %v — refetching server", err)
			time.Sleep(2 * time.Second)
			server, key, ts = t.fetchGroupLPServer()
			continue
		}
		ts = newTS

		for _, ev := range events {
			fromID, text := parseGroupEvent(ev)
			if fromID == 0 || !isWRP(text) {
				continue
			}
			conn, exists := conns[fromID]
			if !exists {
				conn = newBotConn(t, fromID)
				conns[fromID] = conn
				select {
				case t.accept <- conn:
				case <-t.stopChan:
					return
				}
				log.Info("[vkbot] new client connection from VK user %d", fromID)
			}
			conn.deliver(text)
		}
	}
}


func (t *Transport) sendMessage(peerID int64, text string) error {
	token := t.cfg.UserToken
	if t.cfg.ServerMode {
		token = t.cfg.GroupToken
	}

	params := url.Values{
		"peer_id":   {strconv.FormatInt(peerID, 10)},
		"message":   {text},
		"random_id": {strconv.Itoa(rand.Int())},
		"v":         {vkAPIVersion},
		"access_token": {token},
	}
	resp, err := t.hc.PostForm(vkAPIBase+"/messages.send", params)
	if err != nil {
		return fmt.Errorf("vkbot send: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Error *struct {
			Code int    `json:"error_code"`
			Msg  string `json:"error_msg"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("vkbot send decode: %w", err)
	}
	if result.Error != nil {
		return fmt.Errorf("vkbot API error %d: %s", result.Error.Code, result.Error.Msg)
	}
	return nil
}


type groupLPServer struct {
	Key    string `json:"key"`
	Server string `json:"server"`
	TS     string `json:"ts"`
}

func (t *Transport) fetchGroupLPServer() (server, key, ts string) {
	for {
		select {
		case <-t.stopChan:
			return
		default:
		}

		params := url.Values{
			"group_id":     {strconv.FormatInt(t.cfg.GroupID, 10)},
			"access_token": {t.cfg.GroupToken},
			"v":            {vkAPIVersion},
		}
		resp, err := t.hc.PostForm(vkAPIBase+"/groups.getLongPollServer", params)
		if err != nil {
			log.Warn("[vkbot] fetchGroupLPServer: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		defer resp.Body.Close()

		var result struct {
			Response *groupLPServer `json:"response"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Response == nil {
			log.Warn("[vkbot] fetchGroupLPServer decode error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		r := result.Response
		log.Info("[vkbot] group LP server acquired: %s", r.Server)
		return r.Server, r.Key, r.TS
	}
}

type groupLPResponse struct {
	TS      string            `json:"ts"`
	Updates []json.RawMessage `json:"updates"`
	Failed  int               `json:"failed"`
}

func (t *Transport) pollGroup(server, key, ts string) (events []json.RawMessage, newTS string, err error) {
	reqURL := fmt.Sprintf("%s?act=a_check&key=%s&ts=%s&wait=25",
		server, url.QueryEscape(key), url.QueryEscape(ts))

	resp, err := t.hc.Get(reqURL)
	if err != nil {
		return nil, ts, err
	}
	defer resp.Body.Close()

	var result groupLPResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, ts, err
	}

	switch result.Failed {
	case 0:
		return result.Updates, result.TS, nil
	case 1:
		return nil, result.TS, nil
	case 2, 3:
		return nil, ts, fmt.Errorf("LP failed=%d", result.Failed)
	}
	return result.Updates, result.TS, nil
}

type groupMsgEvent struct {
	Type   string `json:"type"`
	Object struct {
		Message struct {
			FromID int64  `json:"from_id"`
			Text   string `json:"text"`
		} `json:"message"`
	} `json:"object"`
}

func parseGroupEvent(raw json.RawMessage) (fromID int64, text string) {
	var ev groupMsgEvent
	if err := json.Unmarshal(raw, &ev); err != nil || ev.Type != "message_new" {
		return 0, ""
	}
	return ev.Object.Message.FromID, ev.Object.Message.Text
}


type userLPServer struct {
	Key    string      `json:"key"`
	Server string      `json:"server"`
	TS     json.Number `json:"ts"`
}

func (t *Transport) fetchUserLPServer() (server, key, ts string, err error) {
	params := url.Values{
		"lp_version":   {"3"},
		"access_token": {t.cfg.UserToken},
		"v":            {vkAPIVersion},
	}
	resp, err := t.hc.PostForm(vkAPIBase+"/messages.getLongPollServer", params)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	var result struct {
		Response *userLPServer `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Response == nil {
		return "", "", "", fmt.Errorf("user LP server decode: %w", err)
	}
	r := result.Response
	srv := r.Server
	if !strings.HasPrefix(srv, "https://") {
		srv = "https://" + srv
	}
	return srv, r.Key, r.TS.String(), nil
}

type userLPResponse struct {
	TS      json.Number       `json:"ts"`
	Updates []json.RawMessage `json:"updates"`
	Failed  json.Number       `json:"failed"`
}

func (t *Transport) pollUser(server, key, ts string) (msgs []string, newTS string, err error) {
	reqURL := fmt.Sprintf("%s?act=a_check&key=%s&ts=%s&wait=25&mode=2&version=3",
		server, url.QueryEscape(key), url.QueryEscape(ts))

	resp, err := t.hc.Get(reqURL)
	if err != nil {
		return nil, ts, err
	}
	defer resp.Body.Close()

	var result userLPResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, ts, err
	}

	failedStr := result.Failed.String()
	if failedStr != "" && failedStr != "0" && failedStr != "<nil>" {
		failed, _ := strconv.Atoi(failedStr)
		switch failed {
		case 1:
			return nil, result.TS.String(), nil
		case 2, 3:
			return nil, ts, fmt.Errorf("user LP failed=%d", failed)
		}
	}

	communityPeerID := communityPeerOffset + t.cfg.GroupID

	for _, raw := range result.Updates {
		var upd []json.RawMessage
		if err := json.Unmarshal(raw, &upd); err != nil || len(upd) < 7 {
			continue
		}
		var eventType int
		json.Unmarshal(upd[0], &eventType)
		if eventType != 4 {
			continue
		}
		var peerID int64
		json.Unmarshal(upd[3], &peerID)
		if peerID != communityPeerID {
			continue
		}
		var text string
		json.Unmarshal(upd[6], &text)
		if isWRP(text) {
			msgs = append(msgs, text)
		}
	}
	return msgs, result.TS.String(), nil
}


func encodeMsg(seq uint32, total, chunk int, payload []byte) string {
	hdr := make([]byte, 6)
	binary.BigEndian.PutUint32(hdr[0:4], seq)
	hdr[4] = byte(total)
	hdr[5] = byte(chunk)
	buf := make([]byte, 6+len(payload))
	copy(buf[:6], hdr)
	copy(buf[6:], payload)
	return msgPrefix + base64.RawURLEncoding.EncodeToString(buf)
}

func decodeMsg(text string) (seq uint32, total, chunk int, payload []byte, err error) {
	if !isWRP(text) {
		return 0, 0, 0, nil, fmt.Errorf("not a WRP message")
	}
	raw, err := base64.RawURLEncoding.DecodeString(text[len(msgPrefix):])
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("base64: %w", err)
	}
	if len(raw) < 6 {
		return 0, 0, 0, nil, fmt.Errorf("too short")
	}
	seq = binary.BigEndian.Uint32(raw[0:4])
	total = int(raw[4])
	chunk = int(raw[5])
	payload = raw[6:]
	return seq, total, chunk, payload, nil
}

func isWRP(text string) bool {
	return strings.HasPrefix(text, msgPrefix)
}


func Factory(cfg interface{}) (interfaces.Module, error) {
	if c, ok := cfg.(*Config); ok {
		return New(c)
	}
	return nil, fmt.Errorf("vkbot: invalid config type")
}

var _ interfaces.Transport = (*Transport)(nil)

var _ = sync.Mutex{}
var _ = atomic.Bool{}
