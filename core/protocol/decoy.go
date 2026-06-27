package protocol

import (
	"context"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type decoyProxy struct {
	origin string
	rp     *httputil.ReverseProxy
}

const jitterCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomJitter(minLen, maxLen int) string {
	n := minLen + mrand.Intn(maxLen-minLen+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = jitterCharset[mrand.Intn(len(jitterCharset))]
	}
	return string(b)
}

func serveDecoy(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
	if cfg != nil && cfg.proxy != nil {
		cfg.proxy.serve(w, r)
		return
	}
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if cfg != nil && cfg.altSvcHeader != "" {
		w.Header().Set("Alt-Svc", cfg.altSvcHeader)
	}

	path := r.URL.Path
	var ct, body string
	switch {
	case strings.HasSuffix(path, ".js"):
		ct = "application/javascript; charset=utf-8"
		body = "(function(){'use strict';/*" + randomJitter(8, 220) + "*/})();\n"
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	case strings.HasSuffix(path, ".css"):
		ct = "text/css; charset=utf-8"
		body = "*{box-sizing:border-box}body{margin:0}/*" + randomJitter(8, 220) + "*/\n"
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	case strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, "health") ||
		strings.HasSuffix(path, "config"):
		ct = "application/json; charset=utf-8"
		body = `{"status":"ok","version":"1.0.0","_t":"` + randomJitter(4, 96) + `"}` + "\n"
		w.Header().Set("Cache-Control", "no-cache")
	case strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".woff2"):
		switch {
		case strings.HasSuffix(path, ".ico"):
			ct = "image/x-icon"
		case strings.HasSuffix(path, ".png"):
			ct = "image/png"
		case strings.HasSuffix(path, ".woff2"):
			ct = "font/woff2"
		}
		body = randomJitter(180, 4096)
		w.Header().Set("Cache-Control", "public, max-age=86400")
	case path == "/robots.txt":
		ct = "text/plain; charset=utf-8"
		body = "User-agent: *\nDisallow: /api/\n# " + randomJitter(4, 96) + "\n"
		w.Header().Set("Cache-Control", "public, max-age=86400")
	case path == "/manifest.json":
		ct = "application/json; charset=utf-8"
		body = `{"name":"","short_name":"","start_url":"/","display":"standalone","icons":[],"_t":"` + randomJitter(4, 96) + `"}` + "\n"
		w.Header().Set("Cache-Control", "public, max-age=3600")
	default:
		ct = "text/html; charset=utf-8"
		body = "<!DOCTYPE html><html><head><title></title></head><body><!--" + randomJitter(16, 600) + "--></body></html>\n"
		w.Header().Set("Cache-Control", "max-age=3600")
	}

	w.Header().Set("Content-Type", ct)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	if body != "" {
		io.WriteString(w, body)
	}
}

func runDecoy(ctx context.Context, client *http.Client, serverAddr, sni, origin string, bp BehaviorParams, fc *FrameConn, prof browserProfile) {
	get := func(path string) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("https://%s%s", serverAddr, path), nil)
		if err != nil {
			return
		}
		req.Host = sni
		prof.apply(req, origin)
		if resp, err := client.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	loadFactor := func() int {
		if fc == nil {
			return 1
		}
		bytes := fc.SampleAndResetBytes()
		switch {
		case bytes > 4<<20:
			return 8
		case bytes > 1<<20:
			return 4
		case bytes > 256<<10:
			return 2
		default:
			return 1
		}
	}

	burstFor := func(base int) int {
		if fc == nil {
			return base
		}
		recent := atomic.LoadUint64(&fc.bytesRecent)
		switch {
		case recent > 4<<20:
			return 1
		case recent > 1<<20:
			if base > 2 {
				return 2
			}
		}
		return base
	}

	heavyLoad := func() bool {
		if fc == nil {
			return false
		}
		return atomic.LoadUint64(&fc.bytesRecent) > 4<<20
	}

	sleep := func(ms int) bool {
		ms *= loadFactor()
		jitter := time.Duration(mrand.Intn(ms/4+1)) * time.Millisecond
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Duration(ms)*time.Millisecond + jitter):
			return true
		}
	}

	parallel := func(paths []string, n int) {
		if n > len(paths) {
			n = len(paths)
		}
		chosen := mrand.Perm(len(paths))[:n]
		var wg sync.WaitGroup
		for _, i := range chosen {
			wg.Add(1)
			p := paths[i]
			go func() { defer wg.Done(); get(p) }()
			time.Sleep(time.Duration(mrand.Intn(20)) * time.Millisecond)
		}
		wg.Wait()
	}

	go func() {
		api := decoyGraph[3]
		for {
			ms := 3000 + mrand.Intn(5001)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
			if heavyLoad() {
				continue
			}
			get(api[mrand.Intn(len(api))])
		}
	}()

	shouldSkip := func() bool {
		if fc == nil {
			return false
		}
		return atomic.LoadUint64(&fc.bytesRecent) > 8<<20
	}

	for {
		if shouldSkip() {
			if !sleep(bp.ParseDelayMs * 4) {
				return
			}
			continue
		}
		nav := decoyGraph[0]
		get(nav[mrand.Intn(len(nav))])
		if !sleep(bp.ParseDelayMs) {
			return
		}

		parallel(decoyGraph[1], burstFor(bp.BurstSize))
		if !sleep(20) {
			return
		}

		parallel(decoyGraph[2], burstFor(1+mrand.Intn(2)))
		if !sleep(bp.ParseDelayMs / 2) {
			return
		}

		api := decoyGraph[3]
		get(api[mrand.Intn(len(api))])

		if !sleep(bp.IdleSec * 1000) {
			return
		}
	}
}

func newDecoyProxy(origin string) *decoyProxy {
	origin = strings.TrimRight(origin, "/")
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return &decoyProxy{origin: origin}
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		serveDecoy(w, r, nil)
	}
	return &decoyProxy{origin: origin, rp: rp}
}

func (p *decoyProxy) serve(w http.ResponseWriter, r *http.Request) {
	if p.rp == nil {
		serveDecoy(w, r, nil)
		return
	}
	p.rp.ServeHTTP(w, r)
}
