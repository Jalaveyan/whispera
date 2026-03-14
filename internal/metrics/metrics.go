package metrics

import "sync/atomic"
type Counter struct {
	value int64
}
func (c *Counter) Inc() {
	atomic.AddInt64(&c.value, 1)
}
func (c *Counter) Add(v float64) {
	atomic.AddInt64(&c.value, int64(v))
}
func (c *Counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}
type CounterVec struct {
	counters map[string]*Counter
}
func NewCounterVec() *CounterVec {
	return &CounterVec{
		counters: make(map[string]*Counter),
	}
}
func (cv *CounterVec) WithLabelValues(labels ...string) *Counter {
	key := ""
	for _, l := range labels {
		key += l + ":"
	}
	if c, ok := cv.counters[key]; ok {
		return c
	}
	c := &Counter{}
	cv.counters[key] = c
	return c
}

var (
	PacketsRx            = &Counter{}
	PacketsTx            = &Counter{}
	BytesRx              = &Counter{}
	BytesTx              = &Counter{}
	PacketsRxByTransport = NewCounterVec()
	PacketsTxByTransport = NewCounterVec()
	BytesRxByTransport   = NewCounterVec()
	BytesTxByTransport   = NewCounterVec()

	XHTTPStreamsCreated   = &Counter{}
	XHTTPSessionsCreated  = &Counter{}
	XHTTPSessionsActive   = &Gauge{}
	XHTTPSessionDuration  = &Histogram{}
	XHTTPSessionsTimeout  = &Counter{}
	XHTTPBufferPoolHits   = &Counter{}
	XHTTPBufferPoolMisses = &Counter{}
)

type Gauge struct {
	value int64
}
func (g *Gauge) Inc() {
	atomic.AddInt64(&g.value, 1)
}
func (g *Gauge) Dec() {
	atomic.AddInt64(&g.value, -1)
}
func (g *Gauge) Set(v float64) {
	atomic.StoreInt64(&g.value, int64(v))
}

func (g *Gauge) Value() int64 {
	return atomic.LoadInt64(&g.value)
}
type Histogram struct {
	count int64
	sum   int64
}
func (h *Histogram) Observe(v float64) {
	atomic.AddInt64(&h.count, 1)
	atomic.AddInt64(&h.sum, int64(v))
}
