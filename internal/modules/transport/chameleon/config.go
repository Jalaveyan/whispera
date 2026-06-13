package chameleon

import (
	"context"
	"net"
	"sync"
	"time"
)

// ClientConfig contains only the fields relevant to the outgoing tunnel client.
type ClientConfig struct {
	ServerAddr    string
	ServerName    string
	ServerNames   []string
	SharedSecret  []byte
	ServerCertPin string
	SessionCache  any
	TCPDialer     func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ServerConfig contains only the fields relevant to the server listener.
type ServerConfig struct {
	ListenAddr    string
	TLSCert       string
	TLSKey        string
	Domain        string
	ACMEDir       string
	DecoyOrigin   string
	AsymBiasRatio float64
	SharedSecret  []byte

	GetUsers  func() []UserEntry
	OnConn    func(conn net.Conn, userID string)
	GANDecide GANDecideFunc

	proxy       *decoyProxy
	sessions    sync.Map
	sessionMu   sync.Mutex
	sessionCond *sync.Cond

	seenTokensMu sync.Mutex
	seenTokens   map[string]int64
}

func (cfg *ServerConfig) consumeToken(token string) bool {
	now := time.Now().Unix()
	cfg.seenTokensMu.Lock()
	defer cfg.seenTokensMu.Unlock()
	if cfg.seenTokens == nil {
		cfg.seenTokens = make(map[string]int64)
	}
	if t, ok := cfg.seenTokens[token]; ok && now-t < 90 {
		return false
	}
	cfg.seenTokens[token] = now
	if len(cfg.seenTokens) > 1000 {
		for k, t := range cfg.seenTokens {
			if now-t >= 90 {
				delete(cfg.seenTokens, k)
			}
		}
	}
	return true
}

func (cfg *ServerConfig) initCond() {
	if cfg.sessionCond == nil {
		cfg.sessionCond = sync.NewCond(&cfg.sessionMu)
	}
}

func (cfg *ServerConfig) storeSession(key string, sess *restSession) {
	cfg.sessions.Store(key, sess)
	cfg.sessionCond.Broadcast()
}

func (cfg *ServerConfig) waitSession(key string, timeout time.Duration) (*restSession, bool) {
	deadline := time.Now().Add(timeout)
	cfg.sessionMu.Lock()
	defer cfg.sessionMu.Unlock()
	var wakeTimer *time.Timer
	defer func() {
		if wakeTimer != nil {
			wakeTimer.Stop()
		}
	}()
	for {
		if v, ok := cfg.sessions.Load(key); ok {
			return v.(*restSession), true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, false
		}
		if wakeTimer == nil {
			wakeTimer = time.AfterFunc(remaining, cfg.sessionCond.Broadcast)
		}
		cfg.sessionCond.Wait()
	}
}
