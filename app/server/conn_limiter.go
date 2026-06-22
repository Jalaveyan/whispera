package main

import (
	"net"
	"sync"
)

const (
	maxGlobalTCPConns = 10000
	maxTCPConnsPerIP  = 200
)

var (
	connLimiterMu    sync.Mutex
	connLimiterTotal int
	connLimiterPerIP = make(map[string]int)
)

func acquireConnSlot(addr net.Addr) (release func(), ok bool) {
	ip := connLimiterIP(addr)

	connLimiterMu.Lock()
	if connLimiterTotal >= maxGlobalTCPConns || connLimiterPerIP[ip] >= maxTCPConnsPerIP {
		connLimiterMu.Unlock()
		return nil, false
	}
	connLimiterTotal++
	connLimiterPerIP[ip]++
	connLimiterMu.Unlock()

	var once sync.Once
	release = func() {
		once.Do(func() {
			connLimiterMu.Lock()
			connLimiterTotal--
			connLimiterPerIP[ip]--
			if connLimiterPerIP[ip] <= 0 {
				delete(connLimiterPerIP, ip)
			}
			connLimiterMu.Unlock()
		})
	}
	return release, true
}

func connLimiterIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
