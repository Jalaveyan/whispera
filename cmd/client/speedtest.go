package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

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
