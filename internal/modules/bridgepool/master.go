package bridgepool

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type MasterStatus struct {
	MasterID      string    `json:"master_id"`
	MasterAddress string    `json:"master_address"`
	Term          uint64    `json:"term"`
	ElectedAt     time.Time `json:"elected_at"`
	Alive         []string  `json:"alive_ids"`
}

type MasterElector struct {
	selfID      string
	selfAddress string
	registry    *Registry
	httpClient  *http.Client

	mu        sync.RWMutex
	masterID  string
	masterAddr string
	term      uint64
	electedAt time.Time

	upstreamURL    string
	upstreamAlive  int32
	lastUpstreamOK time.Time

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewMasterElector(selfID, selfAddress, upstreamURL string, reg *Registry) *MasterElector {
	return &MasterElector{
		selfID:      selfID,
		selfAddress: selfAddress,
		upstreamURL: upstreamURL,
		registry:    reg,
		httpClient:  &http.Client{Timeout: 3 * time.Second},
		stopCh:      make(chan struct{}),
	}
}

func (me *MasterElector) Start() {
	me.wg.Add(2)
	go me.upstreamWatcher()
	go me.electionLoop()
}

func (me *MasterElector) Stop() {
	close(me.stopCh)
	me.wg.Wait()
}

func (me *MasterElector) upstreamWatcher() {
	defer me.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-me.stopCh:
			return
		case <-ticker.C:
			alive := me.pingUpstream()
			if alive {
				atomic.StoreInt32(&me.upstreamAlive, 1)
				me.mu.Lock()
				me.lastUpstreamOK = time.Now()
				me.mu.Unlock()
			} else {
				atomic.StoreInt32(&me.upstreamAlive, 0)
			}
		}
	}
}

func (me *MasterElector) pingUpstream() bool {
	if me.upstreamURL == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", me.upstreamURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := me.httpClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

func (me *MasterElector) electionLoop() {
	defer me.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-me.stopCh:
			return
		case <-ticker.C:
			if atomic.LoadInt32(&me.upstreamAlive) == 0 {
				me.runElection()
			} else {
				me.mu.Lock()
				me.masterID = ""
				me.masterAddr = ""
				me.mu.Unlock()
			}
		}
	}
}

func (me *MasterElector) runElection() {
	if me.registry == nil {
		return
	}
	alive := me.registry.GetAliveBridges()
	if len(alive) == 0 {
		return
	}

	sort.Slice(alive, func(i, j int) bool {
		li, lj := alive[i].Latency, alive[j].Latency
		if li != lj {
			return li < lj
		}
		return alive[i].ID < alive[j].ID
	})

	elected := alive[0]
	me.mu.Lock()
	prev := me.masterID
	me.masterID = elected.ID
	me.masterAddr = elected.Address
	if prev != elected.ID {
		me.term++
		me.electedAt = time.Now()
	}
	me.mu.Unlock()
}

func (me *MasterElector) GetMaster() MasterStatus {
	me.mu.RLock()
	defer me.mu.RUnlock()
	var aliveIDs []string
	if me.registry != nil {
		for _, b := range me.registry.GetAliveBridges() {
			aliveIDs = append(aliveIDs, b.ID)
		}
	}
	return MasterStatus{
		MasterID:      me.masterID,
		MasterAddress: me.masterAddr,
		Term:          me.term,
		ElectedAt:     me.electedAt,
		Alive:         aliveIDs,
	}
}

func (me *MasterElector) IsMaster() bool {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return me.masterID == me.selfID
}

func (me *MasterElector) UpstreamAlive() bool {
	return atomic.LoadInt32(&me.upstreamAlive) == 1
}

func (me *MasterElector) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/master", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(me.GetMaster())
	})
	mux.HandleFunc("/cluster/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"alive":true}`, me.selfID)
	})
	return mux
}
