package mlserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
	"whispera/neural"
)

var ooniClient = &http.Client{Timeout: 20 * time.Second}

type ooniAggResult struct {
	AnomalyCount     int64 `json:"anomaly_count"`
	ConfirmedCount   int64 `json:"confirmed_count"`
	FailureCount     int64 `json:"failure_count"`
	MeasurementCount int64 `json:"measurement_count"`
	OKCount          int64 `json:"ok_count"`
}

func ooniAggregation(ctx context.Context, cc, testName string) (ooniAggResult, error) {
	since := time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	until := time.Now().Format("2006-01-02")
	u := fmt.Sprintf("https://api.ooni.io/api/v1/aggregation?probe_cc=%s&test_name=%s&since=%s&until=%s",
		cc, testName, since, until)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ooniAggResult{}, err
	}
	resp, err := ooniClient.Do(req)
	if err != nil {
		return ooniAggResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ooniAggResult{}, fmt.Errorf("ooni status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var wrap struct {
		Result ooniAggResult `json:"result"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return ooniAggResult{}, err
	}
	return wrap.Result, nil
}

func (s *MLServer) pollOONI(ctx context.Context, cc string) {
	web, err := ooniAggregation(ctx, cc, "web_connectivity")
	if err != nil {
		s.addLogf("ooni: %s web_connectivity: %v", cc, err)
		return
	}
	tor, _ := ooniAggregation(ctx, cc, "tor")

	oc := neural.OONIContext{UpdatedAt: time.Now().Unix()}
	if web.MeasurementCount > 0 {
		oc.AnomalyRate = float64(web.AnomalyCount+web.ConfirmedCount) / float64(web.MeasurementCount)
		oc.TLSInterference = oc.AnomalyRate
	}
	if tor.MeasurementCount > 0 {
		oc.TorBlocked = float64(tor.AnomalyCount+tor.ConfirmedCount)/float64(tor.MeasurementCount) > 0.5
	}

	s.blockmapMu.Lock()
	if s.ooniByCC == nil {
		s.ooniByCC = make(map[string]neural.OONIContext)
	}
	s.ooniByCC[cc] = oc
	s.blockmapMu.Unlock()
	s.addLogf("ooni: %s anomaly=%.2f tor_blocked=%v", cc, oc.AnomalyRate, oc.TorBlocked)
}

func (s *MLServer) startOONIWorker(countries []string) {
	if len(countries) == 0 {
		return
	}
	go func() {
		ctx := context.Background()
		poll := func() {
			for _, cc := range countries {
				pc, cancel := context.WithTimeout(ctx, 25*time.Second)
				s.pollOONI(pc, cc)
				cancel()
			}
		}
		poll()
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for range t.C {
			poll()
		}
	}()
}
