package fte

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/big"
	"sync"
	"time"
)

// Memory Reuse Pools
var (
	fteRandBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8)
		},
	}

	fteSmallPaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 256)
		},
	}

	fteMediumPaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 1024)
		},
	}

	fteLargePaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 4096)
		},
	}

	fteMLResultChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan []byte, 1)
		},
	}

	fteMLErrorChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan error, 1)
		},
	}
)

// processMLAsync processes data through ML with timeout using channel pools
func processMLAsync(processor func([]byte) ([]byte, error), data []byte, timeout time.Duration) ([]byte, error) {
	resultChan := fteMLResultChanPool.Get().(chan []byte)
	errorChan := fteMLErrorChanPool.Get().(chan error)
	defer fteMLResultChanPool.Put(resultChan)
	defer fteMLErrorChanPool.Put(errorChan)

	go func() {
		result, err := processor(data)
		select {
		case resultChan <- result:
		default:
		}
		select {
		case errorChan <- err:
		default:
		}
	}()

	select {
	case result := <-resultChan:
		<-errorChan
		return result, nil
	case err := <-errorChan:
		<-resultChan
		return nil, err
	case <-time.After(timeout):
		return data, nil // Return original on timeout
	}
}

// Reference methods to silence staticcheck unused warnings
var _ = []interface{}{
	(*FTE).generateRealisticRandomFloat,
	(*FTE).generateRealisticRandomInt,
}

// getPaddingBuffer gets a buffer from pools based on size
func getPaddingBuffer(size int) []byte {
	var pool *sync.Pool
	if size <= 256 {
		pool = &fteSmallPaddingPool
	} else if size <= 1024 {
		pool = &fteMediumPaddingPool
	} else if size <= 4096 {
		pool = &fteLargePaddingPool
	} else {
		return make([]byte, size)
	}

	buf := pool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

// putPaddingBuffer returns buffer to pool
func putPaddingBuffer(buf []byte) {
	if cap(buf) == 0 {
		return
	}

	var pool *sync.Pool
	capSize := cap(buf)
	if capSize <= 256 {
		pool = &fteSmallPaddingPool
	} else if capSize <= 1024 {
		pool = &fteMediumPaddingPool
	} else if capSize <= 4096 {
		pool = &fteLargePaddingPool
	} else {
		return
	}

	pool.Put(buf[:0])
}

// secureRandInt generates a random integer from 0 to max (exclusive) using crypto/rand
func secureRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// secureRandFloat64 generates a random float64 from 0.0 to 1.0 using crypto/rand
func secureRandFloat64() float64 {
	b := fteRandBufferPool.Get().([]byte)
	defer fteRandBufferPool.Put(b)

	if _, err := crand.Read(b); err != nil {
		return 0.0
	}
	val := binary.BigEndian.Uint64(b)
	return float64(val) / float64(^uint64(0))
}

func (fte *FTE) generateRealisticRandomFloat() float64 {
	return secureRandFloat64()
}

func (fte *FTE) generateRealisticRandomInt(n int) int {
	return secureRandInt(n)
}

// formatting.go logic

func (fte *FTE) applyFormat(data []byte, profile *ProtocolProfile) []byte {
	var formatted []byte
	switch profile.Name {
	case "HTTP/2":
		formatted = fte.formatHTTP2(data)
	case "WebSocket":
		formatted = fte.formatWebSocket(data)
	case "QUIC":
		formatted = fte.formatQUIC(data)
	case "TLS":
		formatted = fte.formatTLS(data)
	default:
		formatted = data
	}
	if profile.Regex.Match(formatted) {
		return formatted
	}
	return fte.ensureRegexMatch(formatted, profile)
}

func (fte *FTE) ensureRegexMatch(data []byte, profile *ProtocolProfile) []byte {
	// SAFEGUARD: Do not modify payload to match regex.
	// Forcing binary data (TLS/Encrypted) to match a regex (e.g. Base64/ASCII)
	// by overwriting bytes triggers data corruption and connection failure.
	return data
}

func (fte *FTE) formatHTTP2(data []byte) []byte     { return data }
func (fte *FTE) formatWebSocket(data []byte) []byte { return data }
func (fte *FTE) formatQUIC(data []byte) []byte      { return data }
func (fte *FTE) formatTLS(data []byte) []byte       { return data }

// helpers.go logic

func (fte *FTE) selectWeightedSize(sizes []int, weights []float64) int {
	const maxSafeMTU = 1400
	if len(sizes) != len(weights) {
		return sizes[0]
	}
	totalWeight := 0.0
	for _, w := range weights {
		totalWeight += w
	}
	if totalWeight <= 0 {
		return sizes[0]
	}

	selectionValue := secureRandFloat64() * totalWeight
	cumulative := 0.0
	for i, weight := range weights {
		cumulative += weight
		if selectionValue <= cumulative {
			if sizes[i] > maxSafeMTU {
				return maxSafeMTU
			}
			return sizes[i]
		}
	}
	return sizes[len(sizes)-1]
}
