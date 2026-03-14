package tgbot

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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

var log = logger.Module("tgbot")

const (
	ModuleName    = "transport.tgbot"
	ModuleVersion = "1.0.0"

	tgAPIBase = "https://api.telegram.org/bot"

	msgPrefix = "WRP:"
	maxChunk  = 2000
)

type Config struct {
	MyBotToken string

	GroupChatID int64

	SessionID string

	ServerMode bool
}

func (c *Config) Validate() error {
	if c.MyBotToken == "" {
		return fmt.Errorf("tgbot: MyBotToken required")
	}
	if c.GroupChatID == 0 {
		return fmt.Errorf("tgbot: GroupChatID required")
	}
	return nil
}

func (c *Config) dirPrefix() string {
	if c.ServerMode {
		return "S"
	}
	return "C"
}

func (c *Config) acceptPrefix() string {
	if c.ServerMode {
		return "C"
	}
	return "S"
}

type Transport struct {
	*base.Module
	cfg       *Config
	sessionID string
	hc        *http.Client
	offset    atomic.Int64
	stopChan  chan struct{}
	accept    chan net.Conn
	stopped   atomic.Bool
}

func New(cfg *Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	sid := cfg.SessionID
	if sid == "" {
		b := make([]byte, 6)
		rand.Read(b)
		sid = base64.RawURLEncoding.EncodeToString(b)
	}
	t := &Transport{
		Module:    base.NewModule(ModuleName, ModuleVersion, nil),
		cfg:       cfg,
		sessionID: sid,
		hc:        &http.Client{Timeout: 35 * time.Second},
		stopChan:  make(chan struct{}),
		accept:    make(chan net.Conn, 32),
	}
	return t, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportTGBot }
func (t *Transport) Listen(addr string) error        { return nil }

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}
	if t.cfg.ServerMode {
		go t.listenLoop()
	}
	t.SetHealthy(true, fmt.Sprintf("session=%s group=%d", t.sessionID, t.cfg.GroupChatID))
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
	conn := newBotConn(t)
	ctx2, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-t.stopChan:
			cancel()
		case <-ctx2.Done():
		}
	}()
	go conn.pollLoop(ctx2, cancel)
	return conn, nil
}


func (t *Transport) listenLoop() {
	conns := make(map[string]*botConn)

	for {
		select {
		case <-t.stopChan:
			return
		default:
		}

		msgs, err := t.getUpdates(25)
		if err != nil {
			log.Warn("[tgbot] getUpdates error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		for _, m := range msgs {
			key := strconv.FormatInt(m.senderID, 10) + ":" + m.sessionID
			conn, exists := conns[key]
			if !exists {
				conn = newBotConn(t)
				conns[key] = conn
				select {
				case t.accept <- conn:
					log.Info("[tgbot] new client connection key=%s", key)
				case <-t.stopChan:
					return
				}
			}
			conn.deliver(m.text)
		}
	}
}


type incomingMsg struct {
	senderID  int64
	sessionID string
	text      string
}

func (t *Transport) getUpdates(timeout int) ([]incomingMsg, error) {
	offset := t.offset.Load()
	reqURL := fmt.Sprintf("%s%s/getUpdates?timeout=%d&offset=%d&allowed_updates=[\"message\"]",
		tgAPIBase, url.PathEscape(t.cfg.MyBotToken), timeout, offset)

	resp, err := t.hc.Get(reqURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		OK     bool `json:"ok"`
		Result []struct {
			UpdateID int64 `json:"update_id"`
			Message  *struct {
				MessageID int64 `json:"message_id"`
				From      struct {
					ID    int64 `json:"id"`
					IsBot bool  `json:"is_bot"`
				} `json:"from"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
				Text string `json:"text"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("tgbot: getUpdates returned ok=false")
	}

	acceptDir := t.cfg.acceptPrefix()
	fullPrefix := msgPrefix + acceptDir

	var msgs []incomingMsg
	for _, upd := range result.Result {
		if upd.UpdateID >= t.offset.Load() {
			t.offset.Store(upd.UpdateID + 1)
		}

		m := upd.Message
		if m == nil {
			continue
		}
		if m.Chat.ID != t.cfg.GroupChatID {
			continue
		}
		if !strings.HasPrefix(m.Text, fullPrefix) {
			continue
		}

		rest := m.Text[len(fullPrefix):]
		colonIdx := strings.IndexByte(rest, ':')
		if colonIdx < 0 {
			continue
		}
		sid := rest[:colonIdx]
		if sid != t.sessionID {
			continue
		}

		msgs = append(msgs, incomingMsg{
			senderID:  m.From.ID,
			sessionID: sid,
			text:      m.Text,
		})
	}
	return msgs, nil
}

func (t *Transport) sendMessage(text string) error {
	params := url.Values{
		"chat_id":              {strconv.FormatInt(t.cfg.GroupChatID, 10)},
		"text":                 {text},
		"disable_notification": {"true"},
	}
	resp, err := t.hc.PostForm(tgAPIBase+url.PathEscape(t.cfg.MyBotToken)+"/sendMessage", params)
	if err != nil {
		return fmt.Errorf("tgbot send: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("tgbot send decode: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("tgbot API error: %s", result.Description)
	}
	return nil
}


func (t *Transport) encodeMsg(seq uint32, total, chunk int, payload []byte) string {
	hdr := make([]byte, 6+len(payload))
	binary.BigEndian.PutUint32(hdr[0:4], seq)
	hdr[4] = byte(total)
	hdr[5] = byte(chunk)
	copy(hdr[6:], payload)
	return msgPrefix + t.cfg.dirPrefix() + t.sessionID + ":" +
		base64.RawURLEncoding.EncodeToString(hdr)
}

func decodeMsg(text string) (seq uint32, total, chunk int, payload []byte, err error) {
	colonIdx := strings.IndexByte(text[len(msgPrefix)+1:], ':')
	if colonIdx < 0 {
		return 0, 0, 0, nil, fmt.Errorf("malformed WRP message")
	}
	dataB64 := text[len(msgPrefix)+1+colonIdx+1:]

	raw, err := base64.RawURLEncoding.DecodeString(dataB64)
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


type botConn struct {
	transport *Transport
	recvMu    sync.Mutex
	recvBuf   []byte
	recvCond  *sync.Cond

	asmMu  sync.Mutex
	frames map[uint32]*frameAsm

	sendSeq   atomic.Uint32
	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}

	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

type frameAsm struct {
	total  int
	chunks map[int][]byte
}

func newBotConn(t *Transport) *botConn {
	c := &botConn{
		transport: t,
		frames:    make(map[uint32]*frameAsm),
		done:      make(chan struct{}),
	}
	c.recvCond = sync.NewCond(&c.recvMu)
	return c
}

func (c *botConn) Write(data []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	total := len(data)
	seq := c.sendSeq.Add(1)

	var chunks [][]byte
	for len(data) > 0 {
		n := maxChunk
		if n > len(data) {
			n = len(data)
		}
		chunks = append(chunks, data[:n])
		data = data[n:]
	}
	if len(chunks) == 0 {
		chunks = [][]byte{{}}
	}
	if len(chunks) > 255 {
		return 0, fmt.Errorf("tgbot: write too large (%d bytes)", total)
	}

	if dl, ok := c.writeDeadline.Load().(time.Time); ok && !dl.IsZero() && time.Now().After(dl) {
		return 0, &net.OpError{Op: "write", Net: "tgbot", Err: fmt.Errorf("i/o timeout")}
	}

	for i, chunk := range chunks {
		msg := c.transport.encodeMsg(seq, len(chunks), i, chunk)
		if err := c.transport.sendMessage(msg); err != nil {
			return 0, err
		}
	}
	return total, nil
}

func (c *botConn) Read(buf []byte) (int, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for len(c.recvBuf) == 0 {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			remaining := time.Until(dl)
			if remaining <= 0 {
				return 0, &net.OpError{Op: "read", Net: "tgbot", Err: fmt.Errorf("i/o timeout")}
			}
			go func() { time.Sleep(remaining); c.recvCond.Broadcast() }()
		}
		c.recvCond.Wait()
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() && time.Now().After(dl) {
			return 0, &net.OpError{Op: "read", Net: "tgbot", Err: fmt.Errorf("i/o timeout")}
		}
	}
	n := copy(buf, c.recvBuf)
	c.recvBuf = c.recvBuf[n:]
	return n, nil
}

func (c *botConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.recvCond.Broadcast()
		close(c.done)
	})
	return nil
}

func (c *botConn) deliver(text string) {
	seq, total, chunkIdx, payload, err := decodeMsg(text)
	if err != nil {
		log.Warn("[tgbot] decode: %v", err)
		return
	}

	c.asmMu.Lock()
	asm, exists := c.frames[seq]
	if !exists {
		asm = &frameAsm{total: total, chunks: make(map[int][]byte)}
		c.frames[seq] = asm
	}
	asm.chunks[chunkIdx] = payload
	if len(asm.chunks) < asm.total {
		c.asmMu.Unlock()
		return
	}
	frame := make([]byte, 0, asm.total*maxChunk)
	for i := 0; i < asm.total; i++ {
		frame = append(frame, asm.chunks[i]...)
	}
	delete(c.frames, seq)
	c.asmMu.Unlock()

	c.recvMu.Lock()
	c.recvBuf = append(c.recvBuf, frame...)
	c.recvCond.Signal()
	c.recvMu.Unlock()
}

func (c *botConn) pollLoop(ctx context.Context, cancel context.CancelFunc) {
	defer func() {
		cancel()
		c.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-c.transport.stopChan:
			return
		default:
		}

		msgs, err := c.transport.getUpdates(25)
		if err != nil {
			log.Warn("[tgbot] client poll error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for _, m := range msgs {
			c.deliver(m.text)
		}
	}
}

func (c *botConn) LocalAddr() net.Addr  { return &tgAddr{"local"} }
func (c *botConn) RemoteAddr() net.Addr { return &tgAddr{fmt.Sprintf("tg:group:%d", c.transport.cfg.GroupChatID)} }

func (c *botConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}
func (c *botConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}
func (c *botConn) SetWriteDeadline(t time.Time) error { c.writeDeadline.Store(t); return nil }

type tgAddr struct{ id string }

func (a *tgAddr) Network() string { return "tgbot" }
func (a *tgAddr) String() string  { return a.id }


func Factory(cfg interface{}) (interfaces.Module, error) {
	if c, ok := cfg.(*Config); ok {
		return New(c)
	}
	return nil, fmt.Errorf("tgbot: invalid config type")
}

var _ interfaces.Transport = (*Transport)(nil)
