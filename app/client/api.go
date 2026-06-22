package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"whispera/core/agent"

	"golang.org/x/net/proxy"
)

func startControlServer(ctx context.Context) {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth", handleAuth)
	mux.HandleFunc("/connections", handleConnections)
	mux.HandleFunc("/connections/", handleConnectionAction)
	mux.HandleFunc("/agent", handleAgent)
	mux.HandleFunc("/agent/recommend", handleAgentRecommend)
	mux.HandleFunc("/agent/report", handleAgentReport)
	mux.HandleFunc("/connections/split", handleConnectionsSplit)
	mux.HandleFunc("/spoof", handleSpoof)
	mux.HandleFunc("/subscription", handleSubscription)
	mux.HandleFunc("/dns", handleDNS)
	mux.HandleFunc("/multi-bridges", handleMultiBridges(ctx))
	mux.HandleFunc("/multi-bridges/", handleMultiBridgeByID)
	mux.HandleFunc("/speedtest", handleSpeedtest)
	mux.HandleFunc("/region", handleRegion)
	mux.HandleFunc("/regions", handleRegions)
	mux.HandleFunc("/global-sni", handleGlobalSNI)
	mux.HandleFunc("/logs", handleLogs)

	srv := &http.Server{Addr: controlAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			stdlog.Printf("Control server error: %v", err)
		}
	}()
	stdlog.Printf("Control server listening on %s", controlAddr)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"username": socksUser,
		"password": socksPass,
	})
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries := pool.List()
	views := make([]entryView, 0, len(entries))
	for _, e := range entries {
		views = append(views, toView(e))
	}
	json.NewEncoder(w).Encode(views)
}

func handleConnectionAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/connections/"), "/")
	if len(parts) < 2 {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	id, action := parts[0], parts[1]
	entry, ok := pool.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch action {
	case "close":
		handleConnClose(w, entry)
	case "toggle":
		handleConnToggle(w, r, entry)
	case "obfuscation":
		handleConnObfuscation(w, r, entry)
	case "transport":
		handleConnTransport(w, r, entry)
	case "port":
		handleConnPort(w, r, entry)
	case "speed":
		handleConnSpeed(w, r, entry)
	case "sni":
		handleConnSNI(w, r, entry)
	case "no_sni":
		handleConnNoSNI(w, r, entry)
	case "duplicate":
		handleConnDuplicate(w, entry)
	case "mux":
		handleConnMux(w, r, entry)
	case "encapsulate":
		handleConnEncapsulate(w, r, entry, id)
	case "tls_fragment":
		handleConnTLSFragment(w, r, entry)
	case "transport_secure":
		handleConnTransportSecure(w, r, entry)
	case "profile":
		handleConnProfile(w, r, entry)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

func handleConnClose(w http.ResponseWriter, entry *TransportEntry) {
	entry.mu.Lock()
	entry.Enabled = false
	entry.Status = connStatusDisconnected
	if entry.cancel != nil {
		entry.cancel()
	}
	entry.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnToggle(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	entry.Enabled = body.Enabled
	if !body.Enabled && entry.cancel != nil {
		entry.cancel()
		entry.Status = connStatusDisconnected
	}
	entry.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnObfuscation(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	entry.Obfuscated = body.Enabled
	entry.ForceObfuscation = body.Enabled
	mgr := entry.mgr
	entry.mu.Unlock()
	if mgr != nil {
		mgr.SetForceObfuscation(body.Enabled)
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnTransport(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Transport string `json:"transport"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Transport != "" {
		entry.mu.Lock()
		entry.Transport = body.Transport
		entry.Status = connStatusConnecting
		entry.mu.Unlock()
		if reconnectEntry != nil {
			go reconnectEntry(entry)
		}
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnPort(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Port string `json:"port"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Port != "" {
		entry.mu.Lock()
		host := entry.Server
		if idx := strings.LastIndex(host, ":"); idx > 0 {
			host = host[:idx]
		}
		entry.Server = host + ":" + body.Port
		entry.Status = connStatusConnecting
		entry.mu.Unlock()
		if reconnectEntry != nil {
			go reconnectEntry(entry)
		}
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnSpeed(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		RateLimitKB int `json:"rate_limit_kb"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	entry.RateLimitKB = body.RateLimitKB
	mgr := entry.mgr
	entry.mu.Unlock()
	if mgr != nil {
		mgr.SetRateLimit(body.RateLimitKB)
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnSNI(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		SNI string `json:"sni"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	entry.SNI = body.SNI
	entry.NoSNI = false
	entry.Status = connStatusConnecting
	entry.mu.Unlock()
	if reconnectEntry != nil {
		go reconnectEntry(entry)
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnNoSNI(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	entry.NoSNI = body.Enabled
	if body.Enabled {
		entry.SNI = ""
	}
	entry.Status = connStatusConnecting
	entry.mu.Unlock()
	if reconnectEntry != nil {
		go reconnectEntry(entry)
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnDuplicate(w http.ResponseWriter, entry *TransportEntry) {
	entry.mu.Lock()
	newEntry := &TransportEntry{
		ID:               pool.NextID(),
		Transport:        entry.Transport,
		Server:           entry.Server,
		Enabled:          true,
		Obfuscated:       entry.Obfuscated,
		ForceObfuscation: entry.ForceObfuscation,
		SNI:              entry.SNI,
		RateLimitKB:      entry.RateLimitKB,
		Mux:              entry.Mux,
		Status:           connStatusConnecting,
	}
	entry.mu.Unlock()
	pool.Add(newEntry)
	if reconnectEntry != nil {
		go reconnectEntry(newEntry)
	}
	json.NewEncoder(w).Encode(map[string]string{"id": newEntry.ID})
}

func handleConnMux(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	entry.Mux = body.Enabled
	entry.Status = connStatusConnecting
	entry.mu.Unlock()
	if reconnectEntry != nil {
		go reconnectEntry(entry)
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnEncapsulate(w http.ResponseWriter, r *http.Request, entry *TransportEntry, id string) {
	var body struct {
		WrapIn string `json:"wrap_in"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if body.WrapIn == id {
		http.Error(w, "cannot encapsulate into itself", http.StatusBadRequest)
		return
	}

	if body.WrapIn != "" {
		if _, exists := pool.Get(body.WrapIn); !exists {
			http.Error(w, "outer tunnel not found", http.StatusNotFound)
			return
		}
	}

	entry.mu.Lock()
	entry.EncapsulatedIn = body.WrapIn
	cb := entry.onEncapsulate
	entry.mu.Unlock()

	if cb != nil {
		go cb(body.WrapIn)
	}

	json.NewEncoder(w).Encode(map[string]string{
		"id":              id,
		"encapsulated_in": body.WrapIn,
	})
}

func handleConnTLSFragment(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Size int `json:"size"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	mgr := entry.mgr
	entry.mu.Unlock()
	if mgr != nil {
		mgr.SetTLSFragmentSize(body.Size)
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnTransportSecure(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	entry.ForceObfuscation = !body.Enabled
	mgr := entry.mgr
	entry.mu.Unlock()
	if mgr != nil {
		mgr.SetForceObfuscation(!body.Enabled)
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnProfile(w http.ResponseWriter, r *http.Request, entry *TransportEntry) {
	var body struct {
		Profile string `json:"profile"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	entry.mu.Lock()
	entry.BehavioralProfile = body.Profile
	mgr := entry.mgr
	entry.mu.Unlock()
	if mgr != nil {
		if err := mgr.SetBehavioralProfile(body.Profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleAgent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if globalAgent == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"state": "disabled"})
		return
	}
	json.NewEncoder(w).Encode(globalAgent.Stats())
}

func handleAgentRecommend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if globalAgent == nil {
		http.Error(w, "agent not running", http.StatusServiceUnavailable)
		return
	}
	transport, server := globalAgent.SelectTransport()
	json.NewEncoder(w).Encode(map[string]string{
		"transport": transport,
		"server":    server,
	})
}

func handleAgentReport(w http.ResponseWriter, r *http.Request) {
	if globalAgent == nil {
		http.Error(w, "agent not running", http.StatusServiceUnavailable)
		return
	}
	var result agent.ProbeResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now()
	}
	globalAgent.ReportResult(result)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleConnectionsSplit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries := pool.List()
	var addrs []string
	for _, e := range entries {
		e.mu.Lock()
		alive := e.Status == connStatusConnected && e.Enabled && e.mgr != nil
		e.mu.Unlock()
		if alive {
			addrs = append(addrs, e.Server)
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(addrs),
		"addrs": addrs,
	})
}

func handleSpoof(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if adminToken != "" && r.Header.Get("X-Admin-Token") != adminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]bool{"ok": false})
		return
	}
	var body struct {
		IPs []string `json:"ips"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	for _, e := range pool.List() {
		e.mu.Lock()
		m := e.mgr
		e.mu.Unlock()
		if m != nil {
			m.SetSpoofIPs(body.IPs)
		}
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleSubscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if globalSubscriptionMgr == nil {
		http.Error(w, `{"error":"no subscription configured"}`, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPost {
		keys, err := globalSubscriptionMgr.ForceRefresh()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		names := make([]string, 0, len(keys))
		for _, k := range keys {
			if k.Name != "" {
				names = append(names, k.Name)
			} else {
				names = append(names, k.Server)
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": names, "count": len(keys)})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"active": globalSubscriptionMgr != nil})
}

func handleDNS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if globalDNS == nil {
		http.Error(w, "dns not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPost {
		var body struct {
			Upstream string `json:"upstream"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		globalDNS.SetUpstream(body.Upstream)
		json.NewEncoder(w).Encode(map[string]string{"upstream": globalDNS.GetUpstream()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"upstream": globalDNS.GetUpstream()})
}

func handleMultiBridges(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if globalMultiRouter == nil {
			http.Error(w, "multi-bridge not available", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			h := globalMultiRouter.HTTPHandler()
			h.ServeHTTP(w, r)
		case http.MethodPost:
			var body struct {
				ID      string   `json:"id"`
				Address string   `json:"address"`
				Rules   []string `json:"rules"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" || body.Address == "" {
				http.Error(w, "id and address required", http.StatusBadRequest)
				return
			}
			globalMultiRouter.AddBridge(body.ID, body.Address, body.Rules, nil)
			if newMultiBridgeTunnel != nil {
				go newMultiBridgeTunnel(ctx, body.ID, body.Address, body.Rules)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func handleMultiBridgeByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if globalMultiRouter == nil {
		http.Error(w, "multi-bridge not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/multi-bridges/")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	globalMultiRouter.RemoveBridge(id)
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleSpeedtest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Target     string `json:"target"`
		Token      string `json:"token"`
		DownloadMB int    `json:"download_mb"`
		UploadMB   int    `json:"upload_mb"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" || req.Token == "" {
		http.Error(w, `{"error":"target and token required"}`, http.StatusBadRequest)
		return
	}
	if req.DownloadMB <= 0 {
		req.DownloadMB = 10
	}
	if req.UploadMB <= 0 {
		req.UploadMB = 5
	}

	result := runSpeedTest(r.Context(), *socksAddr, req.Target, req.Token, req.DownloadMB, req.UploadMB)
	json.NewEncoder(w).Encode(result)
}

func handleRegion(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(map[string]string{"region": getGlobalRegion()})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Region string `json:"region"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Region == "" {
		body.Region = "auto"
	}
	globalRegion.Store(body.Region)
	for _, e := range pool.List() {
		if reconnectEntry != nil {
			go reconnectEntry(e)
		}
	}
	json.NewEncoder(w).Encode(map[string]string{"region": body.Region})
}

func handleRegions(w http.ResponseWriter, r *http.Request) {
	if len(cfgRegions) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"region": getGlobalRegion(), "regions": map[string]interface{}{}})
		return
	}
	type regionInfo struct {
		Servers   []string `json:"servers"`
		LatencyMs float64  `json:"latency_ms,omitempty"`
		Error     string   `json:"error,omitempty"`
	}
	result := make(map[string]*regionInfo, len(cfgRegions))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for code, servers := range cfgRegions {
		code, servers := code, servers
		ri := &regionInfo{Servers: servers}
		result[code] = ri
		wg.Add(1)
		go func() {
			defer wg.Done()
			best := time.Duration(1<<62 - 1)
			for _, srv := range servers {
				conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(context.Background(), "tcp", srv)
				if err != nil {
					continue
				}
				t := time.Now()
				conn.Close()
				lat := time.Since(t)
				if lat < best {
					best = lat
				}
			}
			mu.Lock()
			if best < time.Duration(1<<62-1) {
				ri.LatencyMs = float64(best.Milliseconds())
			} else {
				ri.Error = "unreachable"
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"region":  getGlobalRegion(),
		"regions": result,
	})
}

func handleGlobalSNI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(map[string]string{"sni": getGlobalSNI()})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		SNI string `json:"sni"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	globalForceSNI.Store(body.SNI)

	for _, e := range pool.List() {
		e.mu.Lock()
		hasSNI := e.SNI != ""
		e.mu.Unlock()
		if !hasSNI && reconnectEntry != nil {
			go reconnectEntry(e)
		}
	}
	json.NewEncoder(w).Encode(map[string]string{"sni": body.SNI})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	if globalLogBuf == nil {
		http.Error(w, "logging to file — use tail on the log file instead", http.StatusNotFound)
		return
	}
	lines := globalLogBuf.Lines()
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lines)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, l := range lines {
		io.WriteString(w, l+"\n")
	}
}

type SpeedResult struct {
	LatencyMs    float64 `json:"latency_ms"`
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
	ServerIP     string  `json:"server_ip,omitempty"`
	DownloadMB   int     `json:"download_mb"`
	UploadMB     int     `json:"upload_mb"`
	Error        string  `json:"error,omitempty"`
}

func runSpeedTest(ctx context.Context, proxyAddr, target, token string, downloadMB, uploadMB int) SpeedResult {
	res := SpeedResult{DownloadMB: downloadMB, UploadMB: uploadMB}

	if downloadMB <= 0 {
		downloadMB = 10
		res.DownloadMB = downloadMB
	}
	if uploadMB <= 0 {
		uploadMB = 5
		res.UploadMB = uploadMB
	}

	client, err := buildSOCKS5Client(proxyAddr)
	if err != nil {
		res.Error = fmt.Sprintf("socks5 dial: %v", err)
		return res
	}

	latencies := make([]time.Duration, 0, 5)
	for range 5 {
		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target+"/api/v1/speed/ping", nil)
		resp, err := client.Do(req)
		if err != nil {
			res.Error = fmt.Sprintf("ping: %v", err)
			return res
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		latencies = append(latencies, time.Since(start))
	}
	res.LatencyMs = medianMs(latencies)

	authHdr := "Bearer " + token

	dlURL := fmt.Sprintf("%s/api/v1/speed/download?mb=%d", target, downloadMB)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	req.Header.Set("Authorization", authHdr)

	dlStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.Error = fmt.Sprintf("download: %v", err)
		return res
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		res.ServerIP = resp.TLS.PeerCertificates[0].Subject.CommonName
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	dlElapsed := time.Since(dlStart)
	if dlElapsed > 0 && n > 0 {
		res.DownloadMbps = float64(n) / dlElapsed.Seconds() / (1024 * 1024)
	}

	ulBytes := int64(uploadMB) << 20
	body := io.LimitReader(zeroReader{}, ulBytes)
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, target+"/api/v1/speed/upload", body)
	req.Header.Set("Authorization", authHdr)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = ulBytes

	ulStart := time.Now()
	resp, err = client.Do(req)
	if err != nil {
		res.Error = fmt.Sprintf("upload: %v", err)
		return res
	}
	var ulResp struct {
		Mbps float64 `json:"mbps"`
	}
	json.NewDecoder(resp.Body).Decode(&ulResp)
	resp.Body.Close()
	ulElapsed := time.Since(ulStart)
	if ulResp.Mbps > 0 {
		res.UploadMbps = ulResp.Mbps
	} else if ulElapsed > 0 {
		res.UploadMbps = float64(ulBytes) / ulElapsed.Seconds() / (1024 * 1024)
	}

	return res
}

func buildSOCKS5Client(proxyAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSHandshakeTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   1 * time.Second,
	}, nil
}

func medianMs(ds []time.Duration) float64 {
	if len(ds) == 0 {
		return 0
	}
	min := ds[0]
	for _, d := range ds[1:] {
		if d < min {
			min = d
		}
	}
	return float64(min.Milliseconds())
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
