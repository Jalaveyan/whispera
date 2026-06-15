package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"whispera/internal/ipdetect"
	mlpkg "whispera/internal/obfuscation/ml"

	"github.com/sourcegraph/conc/iter"
)

func (m *Manager) mlHTTPClient() *http.Client {
	if !m.config.MLTLSSkipVerify {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func (m *Manager) ensurePubIP() {
	m.netCtxOnce.Do(func() {
		go func() {
			det := ipdetect.NewIPDetector(nil)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			ip, err := det.DetectExternalIP(ctx)
			if err != nil || ip == "" {
				return
			}
			m.pubIP.Store(ip)
			actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer acancel()
			if asn, cc := lookupASN(actx, ip); asn != "" {
				m.asnVal.Store(asn)
				if cc != "" {
					m.ccVal.Store(cc)
				}
			}
		}()
	})
}

func (m *Manager) networkContext() float64 {
	m.ensurePubIP()
	ip, _ := m.pubIP.Load().(string)
	if ip == "" {
		return 0
	}
	return networkBucket(ip)
}

func (m *Manager) networkKey() (cc, asn string) {
	m.ensurePubIP()
	cc, _ = m.ccVal.Load().(string)
	if a, _ := m.asnVal.Load().(string); a != "" {
		return cc, "AS" + a
	}
	ip, _ := m.pubIP.Load().(string)
	p := net.ParseIP(ip)
	if p == nil {
		return cc, "unknown"
	}
	if p4 := p.To4(); p4 != nil {
		return cc, fmt.Sprintf("%d.%d", p4[0], p4[1])
	}
	return cc, fmt.Sprintf("%02x%02x", p[0], p[1])
}

func lookupASN(ctx context.Context, ip string) (asn, cc string) {
	p := net.ParseIP(ip)
	p4 := p.To4()
	if p4 == nil {
		return "", ""
	}
	name := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", p4[3], p4[2], p4[1], p4[0])
	var r net.Resolver
	txts, err := r.LookupTXT(ctx, name)
	if err != nil || len(txts) == 0 {
		return "", ""
	}
	parts := strings.Split(txts[0], "|")
	if len(parts) >= 3 {
		if f := strings.Fields(parts[0]); len(f) > 0 {
			asn = f[0]
		}
		cc = strings.TrimSpace(parts[2])
	}
	return asn, cc
}

func networkBucket(ip string) float64 {
	p := net.ParseIP(ip)
	if p == nil {
		return 0
	}
	var a, b byte
	if p4 := p.To4(); p4 != nil {
		a, b = p4[0], p4[1]
	} else {
		a, b = p[0], p[1]
	}
	h := (uint32(a)<<8 | uint32(b)) * 2654435761
	v := float64(h%997) / 997.0
	if v == 0 {
		v = 0.001
	}
	return v
}

func (m *Manager) mlRecommendTransport() (transport string, confidence float64) {
	if m.transportAgent == nil {
		return "", 0
	}
	rttMs := float64(atomic.LoadInt64(&m.qualityRTTEWMA)) / 1e6
	missed := float64(atomic.LoadInt32(&m.missedKAs))
	tlsErr := float64(atomic.LoadInt32(&m.tlsErrStreak))
	boFail := float64(atomic.LoadInt32(&m.boFailCount))
	rttScore := 1.0 - math.Min(rttMs/500.0, 1.0)
	kaScore := 1.0 - math.Min(missed/5.0, 1.0)
	successRate := (rttScore + kaScore) / 2.0
	state := m.transportAgent.EncodeState(
		[4]float64{rttMs, rttMs, rttMs, rttMs},
		successRate,
		math.Min((missed+tlsErr)/5.0, 1.0),
		tlsErr >= 2,
		math.Min(tlsErr/5.0, 1.0),
		time.Now().Hour(),
		math.Min((tlsErr+boFail)/6.0, 1.0),
	)
	state[11] = m.networkContext()
	tr, _ := m.transportAgent.Select(state)
	if tr == "" {
		return "", 0
	}
	return tr, 1.0
}

func (m *Manager) mlSendFeedback(transport string, success bool, latencyMs float64) {
	if transport == "" || m.transportAgent == nil {
		return
	}
	m.transportAgent.RecordOutcome(success, latencyMs)
	if !success && m.transportAgent.ShouldRotate() {
		go m.rotateTransport()
	}
}

func (m *Manager) mlStartTransportWatchdog(ctx context.Context) {
	if m.transportAgent == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rec, _ := m.mlRecommendTransport()
				if rec == "" || rec == m.config.Transport {
					continue
				}
				if m.gameLaneActive() {
					continue
				}
				m.config.Transport = rec
				m.rotateTransport()
			}
		}
	}()
}

func (m *Manager) mlBlockmapSync(ctx context.Context) {
	if m.transportAgent == nil || m.config.MLServerURL == "" {
		return
	}
	base := m.config.MLServerURL
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}
	cc, asn := m.networkKey()

	if outcomes := m.transportAgent.DrainOutcomes(); len(outcomes) > 0 {
		body, _ := json.Marshal(mlpkg.BlockReport{CC: cc, ASN: asn, Reports: outcomes})
		uCtx, uCancel := context.WithTimeout(ctx, 10*time.Second)
		if req, err := http.NewRequestWithContext(uCtx, http.MethodPost, base+"/federated/blockreport", bytes.NewReader(body)); err == nil {
			req.Header.Set("Content-Type", "application/json")
			if m.config.MLToken != "" {
				req.Header.Set("Authorization", "Bearer "+m.config.MLToken)
			}
			if resp, derr := m.mlHTTPClient().Do(req); derr == nil {
				resp.Body.Close()
			}
		}
		uCancel()
	}

	dCtx, dCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dCancel()
	req, err := http.NewRequestWithContext(dCtx, http.MethodGet, base+"/federated/blockmap?cc="+cc+"&asn="+asn, nil)
	if err != nil {
		return
	}
	if m.config.MLToken != "" {
		req.Header.Set("Authorization", "Bearer "+m.config.MLToken)
	}
	resp, err := m.mlHTTPClient().Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var e mlpkg.BlockmapEntry
	if json.NewDecoder(resp.Body).Decode(&e) == nil {
		m.transportAgent.ApplyBlockmapPrior(e)
		avoid := make(map[string]bool, len(e.Avoid))
		for _, n := range e.Avoid {
			avoid[n] = true
		}
		m.blockAvoid.Store(avoid)
	}
}

func (m *Manager) mlStartFederatedSync(ctx context.Context) {
	if m.config.MLServerURL == "" {
		return
	}
	m.fedSyncOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			m.mlFederatedSync(ctx)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					m.mlFederatedSync(ctx)
				}
			}
		}()
		go func() {
			bt := time.NewTicker(30 * time.Minute)
			defer bt.Stop()
			m.mlBlockmapSync(ctx)
			for {
				select {
				case <-ctx.Done():
					return
				case <-bt.C:
					m.mlBlockmapSync(ctx)
				}
			}
		}()
	})
}

func (m *Manager) mlFederatedSync(ctx context.Context) {
	base := m.config.MLServerURL
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}

	dlCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, base+"/federated/download", nil)
	if err != nil {
		return
	}
	if m.config.MLToken != "" {
		req.Header.Set("Authorization", "Bearer "+m.config.MLToken)
	}
	resp, _ := m.mlHTTPClient().Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	ulCtx, ulCancel := context.WithTimeout(ctx, 10*time.Second)
	defer ulCancel()
	uploadBody, _ := json.Marshal(map[string]string{"client_id": "go-client", "data": ""})
	ulReq, err := http.NewRequestWithContext(ulCtx, http.MethodPost,
		base+"/federated/upload", bytes.NewReader(uploadBody))
	if err != nil {
		return
	}
	ulReq.Header.Set("Content-Type", "application/json")
	if m.config.MLToken != "" {
		ulReq.Header.Set("Authorization", "Bearer "+m.config.MLToken)
	}
	ulResp, _ := m.mlHTTPClient().Do(ulReq)
	if ulResp != nil {
		ulResp.Body.Close()
	}
}

func probeLatency(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

func (m *Manager) pickServer(ctx context.Context) string {
	candidates := m.regionCandidates()
	if len(candidates) == 0 {
		return ""
	}

	probes := iter.Map(candidates, func(a *string) mlpkg.ServerProbe {
		addr := *a
		lat, err := probeLatency(ctx, addr, 200*time.Millisecond)
		if err != nil {
			return mlpkg.ServerProbe{Addr: addr, Latency: math.MaxInt64}
		}
		return mlpkg.ServerProbe{Addr: addr, Latency: lat}
	})

	if m.serverAgent != nil {
		if chosen := m.serverAgent.Decide(probes); chosen != "" {
			return chosen
		}
	}

	best := probes[0]
	for _, p := range probes[1:] {
		if p.Latency < best.Latency {
			best = p
		}
	}
	if best.Latency == math.MaxInt64 {
		return ""
	}
	return best.Addr
}

func (m *Manager) regionCandidates() []string {
	region := m.config.PreferredRegion
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	if region != "" && region != "auto" {
		if servers, ok := m.config.Regions[region]; ok && len(servers) > 0 {
			for _, s := range servers {
				add(s)
			}
			return out
		}
	}

	for _, s := range m.config.ServerList {
		add(s)
	}
	for _, servers := range m.config.Regions {
		for _, s := range servers {
			add(s)
		}
	}
	return out
}

func (m *Manager) runWeightSnapshotLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	mlpkg.SetGlobalSnapshot(m.ExportMLWeights())
	for range ticker.C {
		mlpkg.SetGlobalSnapshot(m.ExportMLWeights())
	}
}

func (m *Manager) ExportMLWeights() *mlpkg.WeightSnapshot {
	snap := &mlpkg.WeightSnapshot{}
	if m.transportAgent != nil {
		snap.Transport = m.transportAgent.ExportWeights()
	}
	if m.sniAgent != nil {
		snap.SNI = m.sniAgent.ExportWeights()
	}
	if m.kaAgent != nil {
		snap.Keepalive = m.kaAgent.ExportWeights()
	}
	if m.jitterAgent != nil {
		snap.Jitter = m.jitterAgent.ExportWeights()
	}
	if m.chunkAgent != nil {
		snap.Chunk = m.chunkAgent.ExportWeights()
	}
	if m.connAgent != nil {
		snap.Conn = m.connAgent.ExportWeights()
	}
	if m.boAgent != nil {
		snap.Backoff = m.boAgent.ExportWeights()
	}
	if m.serverAgent != nil {
		snap.Server = m.serverAgent.ExportWeights()
	}
	if m.tlsAgent != nil {
		snap.TLS = m.tlsAgent.ExportWeights()
	}
	return snap
}

func (m *Manager) ImportMLWeights(snap *mlpkg.WeightSnapshot) {
	if snap == nil {
		return
	}
	if m.transportAgent != nil && len(snap.Transport) > 0 {
		m.transportAgent.ImportWeights(snap.Transport)
	}
	if m.sniAgent != nil && len(snap.SNI) > 0 {
		m.sniAgent.ImportWeights(snap.SNI)
	}
	if m.kaAgent != nil && len(snap.Keepalive) > 0 {
		m.kaAgent.ImportWeights(snap.Keepalive)
	}
	if m.jitterAgent != nil && len(snap.Jitter) > 0 {
		m.jitterAgent.ImportWeights(snap.Jitter)
	}
	if m.chunkAgent != nil && len(snap.Chunk) > 0 {
		m.chunkAgent.ImportWeights(snap.Chunk)
	}
	if m.connAgent != nil && len(snap.Conn) > 0 {
		m.connAgent.ImportWeights(snap.Conn)
	}
	if m.boAgent != nil && len(snap.Backoff) > 0 {
		m.boAgent.ImportWeights(snap.Backoff)
	}
	if m.serverAgent != nil && len(snap.Server) > 0 {
		m.serverAgent.ImportWeights(snap.Server)
	}
	if m.tlsAgent != nil && len(snap.TLS) > 0 {
		m.tlsAgent.ImportWeights(snap.TLS)
	}
}
