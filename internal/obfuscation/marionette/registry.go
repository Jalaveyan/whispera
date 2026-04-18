package marionette

import (
	"sync"
	"time"

	"whispera/internal/obfuscation/behavioral"
)

var liveRegistry sync.Map

func registerLiveConn(c *ChatFSMConn) {
	liveRegistry.Store(c.id, c)
}

func unregisterLiveConn(c *ChatFSMConn) {
	liveRegistry.Delete(c.id)
}

func LiveConns() []*ChatFSMConn {
	var conns []*ChatFSMConn
	liveRegistry.Range(func(_, v any) bool {
		if c, ok := v.(*ChatFSMConn); ok {
			conns = append(conns, c)
		}
		return true
	})
	return conns
}

func LiveConnByID(id uint64) *ChatFSMConn {
	v, ok := liveRegistry.Load(id)
	if !ok {
		return nil
	}
	c, _ := v.(*ChatFSMConn)
	return c
}

func BroadcastSetProfile(p *behavioral.MessengerProfile) int {
	if p == nil {
		return 0
	}
	n := 0
	liveRegistry.Range(func(_, v any) bool {
		if c, ok := v.(*ChatFSMConn); ok {
			c.SetProfile(p)
			n++
		}
		return true
	})
	return n
}

func BroadcastSetCoverEnabled(enabled bool) int {
	n := 0
	liveRegistry.Range(func(_, v any) bool {
		if c, ok := v.(*ChatFSMConn); ok {
			c.SetCoverEnabled(enabled)
			n++
		}
		return true
	})
	return n
}

func BroadcastSetCoverInterval(d time.Duration) int {
	n := 0
	liveRegistry.Range(func(_, v any) bool {
		if c, ok := v.(*ChatFSMConn); ok {
			c.SetCoverInterval(d)
			n++
		}
		return true
	})
	return n
}

func LiveCount() int {
	n := 0
	liveRegistry.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}
