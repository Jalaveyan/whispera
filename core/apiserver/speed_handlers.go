package apiserver

import (
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

const (
	speedMaxDownloadMB = 100
	speedMaxUploadMB   = 100
	speedChunkSize     = 32 * 1024
)

func (s *Server) handleSpeedPing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s.jsonOK(w, map[string]int64{"ts": time.Now().UnixMilli()})
}

func (s *Server) handleSpeedDownload(w http.ResponseWriter, r *http.Request) {
	mb := 10
	if v := r.URL.Query().Get("mb"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			mb = n
		}
	}
	if mb > speedMaxDownloadMB {
		mb = speedMaxDownloadMB
	}
	total := int64(mb) << 20

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
	w.Header().Set("Cache-Control", "no-store")

	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Now().Add(5 * time.Minute))

	buf := make([]byte, speedChunkSize)
	rand.Read(buf)

	var written int64
	for written < total {
		n := int64(speedChunkSize)
		if written+n > total {
			n = total - written
		}
		nw, err := w.Write(buf[:n])
		written += int64(nw)
		if err != nil {
			return
		}
	}
}

func (s *Server) handleSpeedUpload(w http.ResponseWriter, r *http.Request) {
	const maxBody = speedMaxUploadMB << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(5 * time.Minute))

	start := time.Now()
	n, err := io.Copy(io.Discard, r.Body)
	elapsed := time.Since(start)

	if err != nil && n == 0 {
		s.jsonError(w, http.StatusBadRequest, "upload read failed")
		return
	}

	var mbps float64
	if elapsed > 0 {
		mbps = float64(n) / elapsed.Seconds() / (1024 * 1024)
	}

	s.jsonOK(w, map[string]interface{}{
		"bytes":     n,
		"elapsed_s": elapsed.Seconds(),
		"mbps":      mbps,
	})
}
