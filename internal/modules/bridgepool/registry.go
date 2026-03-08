package bridgepool

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

type BridgeType string

const (
	BridgeOperator  BridgeType = "operator"  
	BridgeCommunity BridgeType = "community" 
	BridgeUser      BridgeType = "user"      
)

type BridgeInfo struct {
	ID         string     `json:"id"`
	Address    string     `json:"address"` 
	Type       BridgeType `json:"type"`
	Provider   string     `json:"provider"`    
	Region     string     `json:"region"`      
	TrustLevel int        `json:"trust_level"` 
	IsAlive    bool       `json:"is_alive"`
	Latency    int        `json:"latency_ms"`
	PublicKey  string     `json:"public_key"` 
	LastCheck  time.Time  `json:"last_check"`
	CreatedAt  time.Time  `json:"created_at"`
	OwnerID    string     `json:"owner_id"` 
}

type Registry struct {
	bridges       map[string]*BridgeInfo
	mu            sync.RWMutex
	persistPath   string
	healthMonitor *HealthMonitor
}

func NewRegistry(persistPath string) *Registry {
	r := &Registry{
		bridges:     make(map[string]*BridgeInfo),
		persistPath: persistPath,
	}
	r.healthMonitor = NewHealthMonitor(r, 30*time.Second)
	r.load()
	return r
}

func (r *Registry) RegisterBridge(info *BridgeInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if info.ID == "" {
		info.ID = generateBridgeID()
	}
	if info.CreatedAt.IsZero() {
		info.CreatedAt = time.Now()
	}
	// IsAlive starts as false — status becomes true only after a successful health check.
	// Callers that know the bridge is reachable (e.g. self-registration) may set it to true
	// before calling RegisterBridge.
	info.LastCheck = time.Now()

	if info.TrustLevel == 0 {
		switch info.Type {
		case BridgeOperator:
			info.TrustLevel = 100
		case BridgeCommunity:
			info.TrustLevel = 50
		case BridgeUser:
			info.TrustLevel = 75
		}
	}

	r.bridges[info.ID] = info
	return r.persist()
}

func (r *Registry) UnregisterBridge(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.bridges[id]; !exists {
		return errors.New("bridge not found")
	}
	delete(r.bridges, id)
	return r.persist()
}

func (r *Registry) GetBridge(id string) (*BridgeInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	b, exists := r.bridges[id]
	if !exists {
		return nil, errors.New("bridge not found")
	}
	return b, nil
}

func (r *Registry) GetAllBridges() []*BridgeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*BridgeInfo, 0, len(r.bridges))
	for _, b := range r.bridges {
		result = append(result, b)
	}
	return result
}

func (r *Registry) GetAliveBridges() []*BridgeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*BridgeInfo, 0)
	for _, b := range r.bridges {
		if b.IsAlive {
			result = append(result, b)
		}
	}

	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].TrustLevel > result[i].TrustLevel ||
				(result[j].TrustLevel == result[i].TrustLevel && result[j].Latency < result[i].Latency) {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result
}

func (r *Registry) UpdateBridgeStatus(id string, isAlive bool, latency int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if b, exists := r.bridges[id]; exists {
		b.IsAlive = isAlive
		b.Latency = latency
		b.LastCheck = time.Now()
	}
}

func (r *Registry) StartHealthMonitor() {
	r.healthMonitor.Start()
}
func (r *Registry) StopHealthMonitor() {
	r.healthMonitor.Stop()
}

// CheckBridgeNow запускает немедленную проверку доступности одного моста.
// Возвращает обновлённые is_alive и latency_ms.
func (r *Registry) CheckBridgeNow(id string) (isAlive bool, latencyMS int, err error) {
	return r.healthMonitor.CheckSingle(id)
}

// BridgeStats возвращает сводную статистику по всем мостам.
func (r *Registry) BridgeStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	total := len(r.bridges)
	alive := 0
	sumLatency := 0
	countLatency := 0

	for _, b := range r.bridges {
		if b.IsAlive {
			alive++
			if b.Latency > 0 {
				sumLatency += b.Latency
				countLatency++
			}
		}
	}

	avgLatency := 0
	if countLatency > 0 {
		avgLatency = sumLatency / countLatency
	}

	return map[string]interface{}{
		"total":       total,
		"alive":       alive,
		"dead":        total - alive,
		"avg_latency": avgLatency,
	}
}

func (r *Registry) persist() error {
	if r.persistPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(r.bridges, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.persistPath, data, 0644)
}

func (r *Registry) load() error {
	if r.persistPath == "" {
		return nil
	}
	data, err := os.ReadFile(r.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &r.bridges)
}

func generateBridgeID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
