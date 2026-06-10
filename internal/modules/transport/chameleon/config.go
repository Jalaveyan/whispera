package chameleon

import (
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
	for {
		if v, ok := cfg.sessions.Load(key); ok {
			return v.(*restSession), true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, false
		}
		go func() { time.Sleep(remaining); cfg.sessionCond.Broadcast() }()
		cfg.sessionCond.Wait()
	}
}
