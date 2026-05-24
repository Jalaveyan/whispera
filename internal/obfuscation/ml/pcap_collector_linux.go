//go:build linux && cgo

package ml

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type FlowLabel int

const (
	FlowUnknown FlowLabel = iota
	FlowTunnel
	FlowDecoy
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
	var upSizes, downSizes []float64
	for i := 1; i < len(fa.packets); i++ {
		iats = append(iats, fa.packets[i].ts-fa.packets[i-1].ts)
	}
	for _, p := range fa.packets {
		if p.up {
			upSizes = append(upSizes, float64(p.size))
		} else {
			downSizes = append(downSizes, float64(p.size))
		}
	}
	allSizes := make([]float64, len(fa.packets))
	for i, p := range fa.packets {
		allSizes[i] = float64(p.size)
	}
	_ = downSizes
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

type PCAPCollector struct {
	iface  string
	port   int
	out    chan LabeledFlow
	stopCh chan struct{}
}

func NewPCAPCollector(iface string, port int) *PCAPCollector {
	return &PCAPCollector{
		iface:  iface,
		port:   port,
		out:    make(chan LabeledFlow, 256),
		stopCh: make(chan struct{}),
	}
}

func (c *PCAPCollector) Out() <-chan LabeledFlow { return c.out }
func (c *PCAPCollector) Stop()                   { close(c.stopCh) }

func (c *PCAPCollector) Start() error {
	handle, err := pcap.OpenLive(c.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap: open %s: %w", c.iface, err)
	}
	filter := fmt.Sprintf("tcp and (port %d or port 80)", c.port)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return fmt.Errorf("pcap: bpf filter: %w", err)
	}

	go func() {
		<-c.stopCh
		handle.Close()
	}()

	go c.capture(handle)
	return nil
}

func (c *PCAPCollector) capture(handle *pcap.Handle) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	flows := make(map[string]*flowAccum)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	emit := func(key string, fa *flowAccum) {
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
		case c.out <- LabeledFlow{Features: fa.features(), Label: fa.label}:
		default:
		}
		delete(flows, key)
	}

	for packet := range src.Packets() {
		meta := packet.Metadata()
		ts := float64(meta.Timestamp.UnixNano()) / 1e9
		size := meta.CaptureLength

		var srcIP, dstIP string
		var srcPort, dstPort int

		if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
			l := ip4.(*layers.IPv4)
			srcIP = l.SrcIP.String()
			dstIP = l.DstIP.String()
		} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
			l := ip6.(*layers.IPv6)
			srcIP = l.SrcIP.String()
			dstIP = l.DstIP.String()
		} else {
			continue
		}

		tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			continue
		}
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)

		key := pcapFlowKey(srcIP, dstIP, srcPort, dstPort)
		fa, exists := flows[key]
		if !exists {
			label := FlowRegistry.Get(key)
			if dstPort == 80 || srcPort == 80 {
				label = FlowDecoy
			}
			fa = &flowAccum{key: key, label: label, firstSeen: ts}
			flows[key] = fa
		}

		up := dstPort == c.port || dstPort == 80
		fa.packets = append(fa.packets, struct {
			ts   float64
			size int
			up   bool
		}{ts, size, up})

		if len(fa.packets) >= 200 {
			emit(key, fa)
		}

		select {
		case <-ticker.C:
			for k, f := range flows {
				age := ts - f.firstSeen
				if age > 30 && len(f.packets) > 0 {
					emit(k, f)
				} else if age > 60 {
					delete(flows, k)
				}
			}
		default:
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

