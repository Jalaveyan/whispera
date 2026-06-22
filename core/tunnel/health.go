package tunnel

import "time"

type poolHealthSampler struct {
	m      *Manager
	stopCh chan struct{}
}

func newPoolHealthSampler(m *Manager) *poolHealthSampler {
	return &poolHealthSampler{m: m}
}

func (p *poolHealthSampler) start() {
	m := p.m
	if !m.config.EnableWhispera {
		return
	}
	p.stop()
	stop := make(chan struct{})
	p.stopCh = stop
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			p.sample()
		}
	}()
}

func (p *poolHealthSampler) stop() {
	if p.stopCh != nil {
		select {
		case <-p.stopCh:
		default:
			close(p.stopCh)
		}
		p.stopCh = nil
	}
}

func (p *poolHealthSampler) sample() {
	m := p.m
	m.connMu.RLock()
	pool := append([]*managedConn(nil), m.activePool...)
	m.connMu.RUnlock()

	nowNs := time.Now().UnixNano()
	for _, mc := range pool {
		if mc == nil || mc.session == nil {
			continue
		}
		_, _, rx, tx := mc.session.Stats()
		bytes := rx + tx
		prevBytes := mc.lastSampledBytes.Load()
		prevNs := mc.lastSampleNs.Load()
		mc.lastSampledBytes.Store(bytes)
		mc.lastSampleNs.Store(nowNs)
		if prevNs == 0 {
			continue
		}
		elapsedNs := nowNs - prevNs
		if elapsedNs <= 0 {
			continue
		}
		delta := int64(bytes) - int64(prevBytes)
		if delta < 0 {
			delta = 0
		}
		mbps := float64(delta) * 8 / (float64(elapsedNs) / 1e9) / 1e6
		mc.rateMbpsX100.Store(int64(mbps * 100))
	}
}

func (p *poolHealthSampler) healthy(pool []*managedConn) []*managedConn {
	if len(pool) <= 1 {
		return pool
	}
	rates := make([]int64, 0, len(pool))
	for _, mc := range pool {
		r := mc.rateMbpsX100.Load()
		if r > 0 {
			rates = append(rates, r)
		}
	}
	if len(rates) == 0 {
		return pool
	}
	sortInt64(rates)
	median := rates[len(rates)/2]
	threshold := median * 30 / 100
	if threshold < 200 {
		threshold = 200
	}

	healthy := make([]*managedConn, 0, len(pool))
	for _, mc := range pool {
		r := mc.rateMbpsX100.Load()
		if r == 0 || r >= threshold {
			healthy = append(healthy, mc)
		}
	}
	return healthy
}

func sortInt64(a []int64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
