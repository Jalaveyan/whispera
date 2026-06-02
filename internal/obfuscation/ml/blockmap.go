package ml

type TransportRate struct {
	OK   int64   `json:"ok"`
	Fail int64   `json:"fail"`
	Rate float64 `json:"rate"`
}

type OONIContext struct {
	AnomalyRate     float64 `json:"anomaly_rate"`
	TLSInterference float64 `json:"tls_interference"`
	TorBlocked      bool    `json:"tor_blocked"`
	UDPThrottled    bool    `json:"udp_throttled"`
	UpdatedAt       int64   `json:"updated_at"`
}

type BlockmapEntry struct {
	CC         string                   `json:"cc"`
	ASN        string                   `json:"asn"`
	OONI       OONIContext              `json:"ooni"`
	Transports map[string]TransportRate `json:"transports"`
	Pool       []string                 `json:"pool"`
	Avoid      []string                 `json:"avoid"`
}

type BlockReport struct {
	CC      string                   `json:"cc"`
	ASN     string                   `json:"asn"`
	Reports map[string]TransportRate `json:"reports"`
}

func (a *RLTransportAgent) DrainOutcomes() map[string]TransportRate {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]TransportRate, len(a.outcomes))
	for name, c := range a.outcomes {
		tot := c[0] + c[1]
		rate := 0.0
		if tot > 0 {
			rate = float64(c[0]) / float64(tot)
		}
		out[name] = TransportRate{OK: c[0], Fail: c[1], Rate: rate}
	}
	a.outcomes = make(map[string]*[2]int64)
	return out
}

func (a *RLTransportAgent) ApplyBlockmapPrior(e BlockmapEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	const priorW = 5.0
	for name, r := range e.Transports {
		i, ok := a.transportIndex[name]
		if !ok || i >= len(a.thompson.alpha) || i >= len(a.thompson.beta) {
			continue
		}
		a.thompson.alpha[i] += r.Rate * priorW
		a.thompson.beta[i] += (1 - r.Rate) * priorW
	}
}
