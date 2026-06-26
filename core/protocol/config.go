package protocol

import (
	"context"
	"net"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

type ClientConfig struct {
	ServerAddr    string
	ServerName    string
	ServerNames   []string
	SharedSecret  []byte
	ServerCertPin string
	SessionCache  any
	TCPDialer     func(ctx context.Context, network, addr string) (net.Conn, error)

	EnableQUIC bool
	QUICAddr   string
	OnQUICConn func(*quicgo.Conn)
}

type ServerConfig struct {
	ListenAddr       string
	ExtraListenAddrs []string
	TLSCert          string
	TLSKey           string
	Domain           string
	ACMEDir          string
	DecoyOrigin      string
	DecoyCertDir     string
	AsymBiasRatio    float64
	SharedSecret     []byte

	QUICListenAddr       string
	ExtraQUICListenAddrs []string

	GetUsers         func() []UserEntry
	OnConn           func(conn net.Conn, userID string)
	GANDecide        GANDecideFunc
	IsNeuralDisabled func(userID string) bool

	sessionRegistry
}

func effectiveGANDecide(cfg *ServerConfig, userID string) GANDecideFunc {
	if cfg.GANDecide == nil {
		return nil
	}
	if cfg.IsNeuralDisabled != nil && cfg.IsNeuralDisabled(userID) {
		return func(float64, float64, float64) GANAction { return GANAction{} }
	}
	return cfg.GANDecide
}

type sessionRegistry struct {
	proxy       *decoyProxy
	sessions    sync.Map
	sessionMu   sync.Mutex
	sessionCond *sync.Cond

	seenTokens tokenSeenSet

	altSvcHeader string
}

const replayWindowSeconds = (2*authWindowTolerance + 1) * authWindowSeconds

func (r *sessionRegistry) consumeToken(token string) bool {
	return r.seenTokens.consume(token, time.Now().Unix())
}

func (r *sessionRegistry) initCond() {
	if r.sessionCond == nil {
		r.sessionCond = sync.NewCond(&r.sessionMu)
	}
}

func (r *sessionRegistry) storeSession(key string, sess *restSession) {
	r.sessions.Store(key, sess)
	r.sessionCond.Broadcast()
}

func (r *sessionRegistry) waitSession(key string, timeout time.Duration) (*restSession, bool) {
	deadline := time.Now().Add(timeout)
	r.sessionMu.Lock()
	defer r.sessionMu.Unlock()
	var wakeTimer *time.Timer
	defer func() {
		if wakeTimer != nil {
			wakeTimer.Stop()
		}
	}()
	for {
		if v, ok := r.sessions.Load(key); ok {
			return v.(*restSession), true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, false
		}
		if wakeTimer == nil {
			wakeTimer = time.AfterFunc(remaining, r.sessionCond.Broadcast)
		}
		r.sessionCond.Wait()
	}
}
