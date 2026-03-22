package ml

import (
	mrand "math/rand"
	"time"
)

func (e *NativeMLEngine) PretrainFromPatterns() (int, float64) {
	if e.IsTraining() {
		return 0, 0
	}

	log.Info("Pre-training model from protocol patterns (no saved weights found)...")
	start := time.Now()

	var samples []TrainingSample

	generators := []struct {
		classID int
		dpiType int
		gen     func() []byte
		count   int
	}{
		{0, 0, genTLSHandshake, 400},
		{0, 2, genTLSData, 200},
		{1, 1, genHTTPRequest, 300},
		{1, 1, genHTTPResponse, 200},
		{2, 0, genDNSQuery, 200},
		{3, 0, genQUIC, 150},
		{4, 0, genWireGuard, 100},
		{5, 0, genSSH, 150},
		{6, 0, genOpenVPN, 100},
		{0, 0, genRandomHighEntropy, 100},
		{0, DPITypeTSPURST, genTLSHandshake, 100},
		{0, DPITypeTSPUThrottle, genTLSData, 80},
		{0, DPITypeTSPUReplay, genTLSHandshake, 60},
	}

	for _, g := range generators {
		for i := 0; i < g.count; i++ {
			data := g.gen()
			features := e.ExtractFeatures(data)
			samples = append(samples, TrainingSample{
				Features: features,
				ClassID:  g.classID,
				DPIType:  g.dpiType,
				IsLabeled: true,
			})
		}
	}

	for i := len(samples) - 1; i > 0; i-- {
		j := mrand.Intn(i + 1)
		samples[i], samples[j] = samples[j], samples[i]
	}

	e.mu.Lock()
	for _, s := range samples {
		e.replayBuf.add(s)
		if s.IsLabeled {
			e.labeledBuf.add(s)
		}
	}
	e.mu.Unlock()

	n, acc := e.Train(100)

	log.Info("Pre-training complete: %d samples, accuracy=%.3f, took %s", n, acc, time.Since(start))
	return n, acc
}

func (e *NativeMLEngine) ShouldPretrain() bool {
	return e.lastTrained.IsZero() && e.accuracy <= 0.5
}


func genTLSHandshake() []byte {
	size := 100 + mrand.Intn(400)
	pkt := make([]byte, size)
	pkt[0] = 0x16
	pkt[1] = 0x03
	pkt[2] = byte(1 + mrand.Intn(3))
	pkt[3] = byte((size - 5) >> 8)
	pkt[4] = byte((size - 5) & 0xff)
	pkt[5] = 0x01
	fillCryptoRandom(pkt[6:])
	return pkt
}

func genTLSData() []byte {
	size := 50 + mrand.Intn(1400)
	pkt := make([]byte, size)
	pkt[0] = 0x17
	pkt[1] = 0x03
	pkt[2] = 0x03
	pkt[3] = byte((size - 5) >> 8)
	pkt[4] = byte((size - 5) & 0xff)
	fillCryptoRandom(pkt[5:])
	return pkt
}

func genHTTPRequest() []byte {
	methods := []string{"GET ", "POST", "PUT ", "HEAD"}
	paths := []string{
		"/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"/api/v1/data HTTP/1.1\r\nHost: api.service.com\r\nContent-Type: application/json\r\n\r\n",
		"/index.html HTTP/1.1\r\nHost: www.test.org\r\nAccept: text/html\r\n\r\n",
	}
	method := methods[mrand.Intn(len(methods))]
	path := paths[mrand.Intn(len(paths))]
	return []byte(method + path)
}

func genHTTPResponse() []byte {
	responses := []string{
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n\r\n<html>",
		"HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n\r\n",
		"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
	}
	resp := responses[mrand.Intn(len(responses))]
	return []byte(resp)
}

func genDNSQuery() []byte {
	pkt := make([]byte, 30+mrand.Intn(40))
	pkt[0] = byte(mrand.Intn(256))
	pkt[1] = byte(mrand.Intn(256))
	pkt[2] = 0x01
	pkt[3] = 0x00
	pkt[4] = 0x00
	pkt[5] = 0x01
	domains := []string{"example", "google", "vk", "ok", "mail"}
	tlds := []string{"com", "ru", "net", "org"}
	domain := domains[mrand.Intn(len(domains))]
	tld := tlds[mrand.Intn(len(tlds))]
	pos := 12
	pkt[pos] = byte(len(domain))
	pos++
	copy(pkt[pos:], domain)
	pos += len(domain)
	pkt[pos] = byte(len(tld))
	pos++
	copy(pkt[pos:], tld)
	pos += len(tld)
	pkt[pos] = 0x00
	return pkt[:pos+5]
}

func genQUIC() []byte {
	size := 100 + mrand.Intn(1200)
	pkt := make([]byte, size)
	pkt[0] = 0xc0 | byte(mrand.Intn(16))
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x01
	fillCryptoRandom(pkt[4:])
	return pkt
}

func genWireGuard() []byte {
	pkt := make([]byte, 148)
	pkt[0] = 0x01
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	fillCryptoRandom(pkt[4:])
	return pkt
}

func genSSH() []byte {
	versions := []string{
		"SSH-2.0-OpenSSH_8.9p1\r\n",
		"SSH-2.0-OpenSSH_9.3p1\r\n",
		"SSH-2.0-libssh2_1.10.0\r\n",
	}
	return []byte(versions[mrand.Intn(len(versions))])
}

func genOpenVPN() []byte {
	size := 50 + mrand.Intn(100)
	pkt := make([]byte, size)
	pkt[0] = 0x00
	pkt[1] = 0x0e
	fillCryptoRandom(pkt[2:])
	return pkt
}

func genRandomHighEntropy() []byte {
	size := 50 + mrand.Intn(1400)
	pkt := make([]byte, size)
	fillCryptoRandom(pkt)
	return pkt
}

func fillCryptoRandom(b []byte) {
	for i := range b {
		b[i] = byte(mrand.Intn(256))
	}
}

