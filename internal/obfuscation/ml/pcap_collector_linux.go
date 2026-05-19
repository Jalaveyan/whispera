//go:build linux

package ml

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FlowLabel identifies whether a TCP flow is a VPN tunnel or a real browser (decoy).
type FlowLabel int

const (
	FlowUnknown FlowLabel = iota
	FlowTunnel            // VPN session — negative example for discriminator
	FlowDecoy             // real browser via decoy_origin — positive example
)

// flowKey is the canonical 5-tuple key (sorted so client→server == server→client).
func flowKey(srcIP, dstIP string, srcPort, dstPort int) string {
	a := fmt.Sprintf("%s:%d", srcIP, srcPort)
	b := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if a < b {
		return a + "-" + b
	}
	return b + "-" + a
}

// FlowRegistry lets the application tag connections before pcap sees them.
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
	// server listens on :443; remote is the client side
	key := flowKey(host, "0.0.0.0", port, 443)
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
	key := flowKey(host, "0.0.0.0", port, 443)
	r.mu.Lock()
	delete(r.m, key)
	r.mu.Unlock()
}

// rawPacket is one line parsed from tcpdump output.
type rawPacket struct {
	ts      float64
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	size    int
}

// flowAccum accumulates per-flow stats until the flow is complete.
type flowAccum struct {
	key     string
	label   FlowLabel
	packets []struct {
		ts   float64
		size int
		up   bool // client→server direction
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

// FlowFeatures is the feature vector fed to the GAN discriminator.
type FlowFeatures struct {
	IATMean, IATStd, IATP90      float64
	SizeMean, SizeStd, SizeP90   float64
	UpRatio, BurstSize           float64
	Duration, PacketCount        float64
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

// PCAPCollector captures packets via tcpdump and emits labeled FlowFeatures.
type PCAPCollector struct {
	iface  string
	port   int
	out    chan LabeledFlow
	stopCh chan struct{}
}

// LabeledFlow is a completed flow with its feature vector and label.
type LabeledFlow struct {
	Features FlowFeatures
	Label    FlowLabel // FlowTunnel or FlowDecoy
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

func (c *PCAPCollector) Start() error {
	// tcpdump -i <iface> -l -n -q -tt port <port>
	// -tt: absolute timestamps (epoch.microseconds)
	// -q: quiet (less headers)
	// -n: no DNS
	cmd := exec.Command("tcpdump",
		"-i", c.iface,
		"-l", "-n", "-q", "-tt",
		fmt.Sprintf("port %d or port 80", c.port),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pcap: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("pcap: start tcpdump: %w", err)
	}

	go func() {
		<-c.stopCh
		cmd.Process.Kill()
	}()

	go c.parse(bufio.NewScanner(stdout))
	return nil
}

func (c *PCAPCollector) Stop() { close(c.stopCh) }

// parse reads tcpdump output lines and emits labeled flows.
// Example line:
//   1716057600.123456 IP 1.2.3.4.54321 > 5.6.7.8.443: tcp 1234
func (c *PCAPCollector) parse(sc *bufio.Scanner) {
	flows := make(map[string]*flowAccum)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	emit := func(key string, fa *flowAccum) {
		if fa.label == FlowUnknown || len(fa.packets) < 5 {
			return
		}
		select {
		case c.out <- LabeledFlow{Features: fa.features(), Label: fa.label}:
		default:
		}
		delete(flows, key)
	}

	for sc.Scan() {
		line := sc.Text()
		pkt, ok := parseTcpdumpLine(line)
		if !ok {
			continue
		}

		key := flowKey(pkt.srcIP, pkt.dstIP, pkt.srcPort, pkt.dstPort)
		fa, exists := flows[key]
		if !exists {
			label := FlowRegistry.Get(key)
			// port 80 = decoy_origin traffic
			if pkt.dstPort == 80 || pkt.srcPort == 80 {
				label = FlowDecoy
			}
			fa = &flowAccum{key: key, label: label, firstSeen: pkt.ts}
			flows[key] = fa
		}

		up := pkt.dstPort == c.port || pkt.dstPort == 80
		fa.packets = append(fa.packets, struct {
			ts   float64
			size int
			up   bool
		}{pkt.ts, pkt.size, up})

		// Emit after 200 packets or 30s of data.
		if len(fa.packets) >= 200 {
			emit(key, fa)
		}

		// Periodic cleanup of stale flows.
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			_ = now
			for k, f := range flows {
				if len(f.packets) > 0 {
					age := pkt.ts - f.firstSeen
					if age > 30 {
						emit(k, f)
					}
				}
			}
		default:
		}
	}
}

// parseTcpdumpLine parses one line of tcpdump -q -tt -n output.
func parseTcpdumpLine(line string) (rawPacket, bool) {
	// 1716057600.123456 IP 1.2.3.4.54321 > 5.6.7.8.443: tcp 1234
	parts := strings.Fields(line)
	if len(parts) < 7 {
		return rawPacket{}, false
	}
	ts, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return rawPacket{}, false
	}
	if parts[1] != "IP" {
		return rawPacket{}, false
	}
	src, ok := parseAddr(parts[2])
	if !ok {
		return rawPacket{}, false
	}
	// parts[3] == ">"
	dst, ok := parseAddr(strings.TrimSuffix(parts[4], ":"))
	if !ok {
		return rawPacket{}, false
	}
	size := 0
	if len(parts) >= 7 {
		size, _ = strconv.Atoi(parts[len(parts)-1])
	}
	return rawPacket{ts: ts, srcIP: src[0], srcPort: src[1].(int), dstIP: dst[0], dstPort: dst[1].(int), size: size}, true
}

// parseAddr splits "1.2.3.4.54321" → ("1.2.3.4", 54321).
func parseAddr(s string) ([2]interface{}, bool) {
	idx := strings.LastIndex(s, ".")
	if idx < 0 {
		return [2]interface{}{}, false
	}
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return [2]interface{}{}, false
	}
	return [2]interface{}{s[:idx], port}, true
}

// ── stats helpers ────────────────────────────────────────────────────────────

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
	// simple insertion sort for small slices
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
		if packets[i].ts-packets[i-1].ts < 0.005 { // 5ms window
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
