package neural

import (
	"fmt"
	"net"
	"strconv"
	"sync"
)

func pcapFlowKey(srcIP, dstIP string, srcPort, dstPort int) string {
	a := fmt.Sprintf("%s:%d", srcIP, srcPort)
	b := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if a < b {
		return a + "-" + b
	}
	return b + "-" + a
}

var FlowRegistry = &flowRegistry{m: make(map[string]FlowLabel)}

type flowRegistry struct {
	mu sync.RWMutex
	m  map[string]FlowLabel
}

func (r *flowRegistry) Register(remoteAddr string, label FlowLabel) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return
	}
	port, _ := strconv.Atoi(portStr)
	key := pcapFlowKey(host, "0.0.0.0", port, 443)
	r.mu.Lock()
	r.m[key] = label
	r.mu.Unlock()
}

func (r *flowRegistry) RegisterConn(local, remote net.Addr, label FlowLabel) {
	lh, lp, err := net.SplitHostPort(local.String())
	if err != nil {
		return
	}
	rh, rp, err := net.SplitHostPort(remote.String())
	if err != nil {
		return
	}
	lpInt, _ := strconv.Atoi(lp)
	rpInt, _ := strconv.Atoi(rp)
	key := pcapFlowKey(lh, rh, lpInt, rpInt)
	r.mu.Lock()
	r.m[key] = label
	r.mu.Unlock()
}

func (r *flowRegistry) Get(key string) FlowLabel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.m[key]
}

func (r *flowRegistry) Delete(remoteAddr string) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return
	}
	port, _ := strconv.Atoi(portStr)
	key := pcapFlowKey(host, "0.0.0.0", port, 443)
	r.mu.Lock()
	delete(r.m, key)
	r.mu.Unlock()
}

func (r *flowRegistry) DeleteConn(local, remote net.Addr) {
	lh, lp, err := net.SplitHostPort(local.String())
	if err != nil {
		return
	}
	rh, rp, err := net.SplitHostPort(remote.String())
	if err != nil {
		return
	}
	lpInt, _ := strconv.Atoi(lp)
	rpInt, _ := strconv.Atoi(rp)
	key := pcapFlowKey(lh, rh, lpInt, rpInt)
	r.mu.Lock()
	delete(r.m, key)
	r.mu.Unlock()
}
