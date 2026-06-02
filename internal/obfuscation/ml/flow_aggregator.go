package ml

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
)

type FlowLabel int

const (
	FlowUnknown FlowLabel = iota
	FlowTunnel
	FlowDecoy
)

type FlowFeatures struct {
	IATMean, IATStd, IATP90    float64
	SizeMean, SizeStd, SizeP90 float64
	UpRatio, BurstSize         float64
	Duration, PacketCount      float64
}

func (f FlowFeatures) Vec() []float64 {
	return []float64{
		f.IATMean, f.IATStd, f.IATP90,
		f.SizeMean, f.SizeStd, f.SizeP90,
		f.UpRatio, f.BurstSize,
		f.Duration, f.PacketCount,
	}
}

const FlowFeatureSize = 10

type LabeledFlow struct {
	Features FlowFeatures
	Label    FlowLabel
}

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

type flowAccum struct {
	key     string
	label   FlowLabel
	packets []struct {
		ts   float64
		size int
		up   bool
	}
	firstSeen float64
}

func (fa *flowAccum) features() FlowFeatures {
	if len(fa.packets) < 2 {
		return FlowFeatures{}
	}
	var iats []float64
	var upSizes []float64
	for i := 1; i < len(fa.packets); i++ {
		iats = append(iats, fa.packets[i].ts-fa.packets[i-1].ts)
	}
	for _, p := range fa.packets {
		if p.up {
			upSizes = append(upSizes, float64(p.size))
		}
	}
	allSizes := make([]float64, len(fa.packets))
	for i, p := range fa.packets {
		allSizes[i] = float64(p.size)
	}
	dur := fa.packets[len(fa.packets)-1].ts - fa.firstSeen
	upRatio := 0.0
	if len(fa.packets) > 0 {
		upRatio = float64(len(upSizes)) / float64(len(fa.packets))
	}
	return FlowFeatures{
		IATMean:     mean(iats),
		IATStd:      stddev(iats),
		IATP90:      percentile(iats, 90),
		SizeMean:    mean(allSizes),
		SizeStd:     stddev(allSizes),
		SizeP90:     percentile(allSizes, 90),
		UpRatio:     upRatio,
		BurstSize:   float64(maxBurst(fa.packets)),
		Duration:    dur,
		PacketCount: float64(len(fa.packets)),
	}
}

type flowAggregator struct {
	port  int
	flows map[string]*flowAccum
	out   chan LabeledFlow
}

func newFlowAggregator(port int, out chan LabeledFlow) *flowAggregator {
	return &flowAggregator{
		port:  port,
		flows: make(map[string]*flowAccum),
		out:   out,
	}
}

func (a *flowAggregator) emit(key string, fa *flowAccum) {
	if fa.label == FlowUnknown || len(fa.packets) < 5 {
		return
	}
	if fa.label == FlowDecoy {
		for i, p := range fa.packets {
			iatMs := -1.0
			if i > 0 {
				iatMs = (fa.packets[i].ts - fa.packets[i-1].ts) * 1000.0
			}
			GlobalFlowObserver.UpdateReference(p.size, iatMs)
		}
	}
	select {
	case a.out <- LabeledFlow{Features: fa.features(), Label: fa.label}:
	default:
	}
	delete(a.flows, key)
}

func (a *flowAggregator) observe(ts float64, srcIP, dstIP string, srcPort, dstPort, size int) {
	if srcPort != a.port && dstPort != a.port && srcPort != 80 && dstPort != 80 {
		return
	}
	key := pcapFlowKey(srcIP, dstIP, srcPort, dstPort)
	fa, exists := a.flows[key]
	if !exists {
		label := FlowRegistry.Get(key)
		if dstPort == 80 || srcPort == 80 {
			label = FlowDecoy
		}
		fa = &flowAccum{key: key, label: label, firstSeen: ts}
		a.flows[key] = fa
	}
	up := dstPort == a.port || dstPort == 80
	fa.packets = append(fa.packets, struct {
		ts   float64
		size int
		up   bool
	}{ts, size, up})
	if len(fa.packets) >= 200 {
		a.emit(key, fa)
	}
}

func (a *flowAggregator) sweep(now float64) {
	for k, f := range a.flows {
		age := now - f.firstSeen
		if age > 30 && len(f.packets) > 0 {
			a.emit(k, f)
		} else if age > 60 {
			delete(a.flows, k)
		}
	}
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func stddev(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	m := mean(v)
	s := 0.0
	for _, x := range v {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(v)))
}

func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sorted := make([]float64, len(v))
	copy(sorted, v)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	idx := int(float64(len(sorted)-1) * p / 100.0)
	return sorted[idx]
}

func maxBurst(packets []struct {
	ts   float64
	size int
	up   bool
}) int {
	max, cur := 0, 0
	for i := 1; i < len(packets); i++ {
		if packets[i].ts-packets[i-1].ts < 0.005 {
			cur++
		} else {
			if cur > max {
				max = cur
			}
			cur = 0
		}
	}
	if cur > max {
		max = cur
	}
	return max
}
