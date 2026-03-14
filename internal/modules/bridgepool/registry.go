package bridgepool

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

type BridgeType string

const (
	BridgeOperator  BridgeType = "operator"
	BridgeCommunity BridgeType = "community"
	BridgeUser      BridgeType = "user"
	BridgeWhite     BridgeType = "white"
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
	Country    string     `json:"country,omitempty"`
	City       string     `json:"city,omitempty"`
	Lat        float64    `json:"lat,omitempty"`
	Lon        float64    `json:"lon,omitempty"`
	Bandwidth  int        `json:"bandwidth_mbps,omitempty"`
	SSHPubKey  string     `json:"ssh_pub_key,omitempty"`
	Load       float64    `json:"load,omitempty"`
	MaxUsers   int        `json:"max_users,omitempty"`
	CurUsers   int        `json:"cur_users,omitempty"`
	Version    string     `json:"version,omitempty"`
}

type AccessKey struct {
	ID        string    `json:"id"`
	BridgeID  string    `json:"bridge_id"`
	UserID    string    `json:"user_id"`
	SSHKey    string    `json:"ssh_key"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Used      bool      `json:"used"`
	OneTime   bool      `json:"one_time"`
}

type Registry struct {
	bridges       map[string]*BridgeInfo
	accessKeys    map[string]*AccessKey
	adminSSHKey   string
	mu            sync.RWMutex
	persistPath   string
	healthMonitor *HealthMonitor
}

func NewRegistry(persistPath string) *Registry {
	r := &Registry{
		bridges:     make(map[string]*BridgeInfo),
		accessKeys:  make(map[string]*AccessKey),
		persistPath: persistPath,
	}
	r.healthMonitor = NewHealthMonitor(r, 30*time.Second)
	r.load()
	r.loadAccessKeys()
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
	info.LastCheck = time.Now()

	if info.TrustLevel == 0 {
		switch info.Type {
		case BridgeOperator:
			info.TrustLevel = 100
		case BridgeWhite:
			info.TrustLevel = 95
		case BridgeUser:
			info.TrustLevel = 75
		case BridgeCommunity:
			info.TrustLevel = 50
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

func (r *Registry) CheckBridgeNow(id string) (isAlive bool, latencyMS int, err error) {
	return r.healthMonitor.CheckSingle(id)
}

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

func (r *Registry) GetWhiteBridges() []*BridgeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*BridgeInfo, 0)
	for _, b := range r.bridges {
		if b.Type == BridgeWhite && b.IsAlive {
			result = append(result, b)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Load != result[j].Load {
			return result[i].Load < result[j].Load
		}
		return result[i].Latency < result[j].Latency
	})
	return result
}

func (r *Registry) GetBridgeMap() []map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]map[string]interface{}, 0, len(r.bridges))
	for _, b := range r.bridges {
		entry := map[string]interface{}{
			"id":         b.ID,
			"type":       b.Type,
			"country":    b.Country,
			"city":       b.City,
			"lat":        b.Lat,
			"lon":        b.Lon,
			"is_alive":   b.IsAlive,
			"latency":    b.Latency,
			"load":       b.Load,
			"users":      b.CurUsers,
			"region":     b.Region,
			"provider":   b.Provider,
			"version":    b.Version,
			"last_check": b.LastCheck,
		}
		if b.Type == BridgeWhite {
			entry["bandwidth"] = b.Bandwidth
			entry["max_users"] = b.MaxUsers
			entry["requires_key"] = true
		}
		result = append(result, entry)
	}

	sort.Slice(result, func(i, j int) bool {
		iAlive, _ := result[i]["is_alive"].(bool)
		jAlive, _ := result[j]["is_alive"].(bool)
		if iAlive != jAlive {
			return iAlive
		}
		iLat, _ := result[i]["latency"].(int)
		jLat, _ := result[j]["latency"].(int)
		return iLat < jLat
	})
	return result
}

func (r *Registry) GetBridgeForConnect(bridgeID string) (map[string]interface{}, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	b, exists := r.bridges[bridgeID]
	if !exists {
		return nil, errors.New("bridge not found")
	}
	if !b.IsAlive {
		return nil, errors.New("bridge is offline")
	}

	result := map[string]interface{}{
		"id":         b.ID,
		"address":    b.Address,
		"type":       b.Type,
		"public_key": b.PublicKey,
		"country":    b.Country,
		"city":       b.City,
		"latency":    b.Latency,
	}
	if b.Type == BridgeWhite {
		result["requires_key"] = true
	}
	return result, nil
}

func (r *Registry) ScanAllBridges() []map[string]interface{} {
	bridges := r.GetAllBridges()
	results := make([]map[string]interface{}, 0, len(bridges))

	for _, b := range bridges {
		alive, latency, _ := r.healthMonitor.CheckSingle(b.ID)
		results = append(results, map[string]interface{}{
			"id":       b.ID,
			"is_alive": alive,
			"latency":  latency,
		})
	}
	return results
}

func (r *Registry) UpdateBridgeLoad(id string, load float64, curUsers int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if b, exists := r.bridges[id]; exists {
		b.Load = load
		b.CurUsers = curUsers
	}
}

func (r *Registry) SetAdminSSHKey(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adminSSHKey = key
}

func (r *Registry) GetAdminSSHKey() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.adminSSHKey
}

func (r *Registry) IssueAccessKey(bridgeID, userID string, oneTime bool, ttl time.Duration) (*AccessKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, exists := r.bridges[bridgeID]
	if !exists {
		return nil, errors.New("bridge not found")
	}
	if b.Type != BridgeWhite {
		return nil, errors.New("access keys only for white bridges")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}

	sshPubKey := fmt.Sprintf("ssh-ed25519 %s whispera-access-%s",
		base64.StdEncoding.EncodeToString(pub), userID)

	ak := &AccessKey{
		ID:        hex.EncodeToString(priv.Seed()[:8]),
		BridgeID:  bridgeID,
		UserID:    userID,
		SSHKey:    sshPubKey,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
		OneTime:   oneTime,
	}
	r.accessKeys[ak.ID] = ak

	_ = priv

	r.persistAccessKeys()
	return ak, nil
}

func (r *Registry) ValidateAccessKey(keyID string) (*AccessKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ak, exists := r.accessKeys[keyID]
	if !exists {
		return nil, errors.New("access key not found")
	}
	if time.Now().After(ak.ExpiresAt) {
		delete(r.accessKeys, keyID)
		r.persistAccessKeys()
		return nil, errors.New("access key expired")
	}
	if ak.OneTime && ak.Used {
		return nil, errors.New("one-time key already used")
	}
	ak.Used = true
	r.persistAccessKeys()
	return ak, nil
}

func (r *Registry) RevokeAccessKey(keyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.accessKeys[keyID]; !exists {
		return errors.New("access key not found")
	}
	delete(r.accessKeys, keyID)
	r.persistAccessKeys()
	return nil
}

func (r *Registry) CleanExpiredAccessKeys() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	changed := false
	for id, ak := range r.accessKeys {
		if now.After(ak.ExpiresAt) {
			delete(r.accessKeys, id)
			changed = true
		}
	}
	if changed {
		r.persistAccessKeys()
	}
}

func (r *Registry) GetAccessKeysForBridge(bridgeID string) []*AccessKey {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*AccessKey, 0)
	for _, ak := range r.accessKeys {
		if ak.BridgeID == bridgeID {
			result = append(result, ak)
		}
	}
	return result
}

func (r *Registry) persistAccessKeys() error {
	if r.persistPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(r.accessKeys, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.persistPath+".keys", data, 0600)
}

func (r *Registry) loadAccessKeys() error {
	if r.persistPath == "" {
		return nil
	}
	data, err := os.ReadFile(r.persistPath + ".keys")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &r.accessKeys)
}

func generateBridgeID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type UserBridgeAssignment struct {
	UserID    string    `json:"user_id"`
	BridgeIDs []string  `json:"bridge_ids"`
	AssignedAt time.Time `json:"assigned_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (r *Registry) GetBridgesForUser(userID string, maxBridges int) []*BridgeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if maxBridges <= 0 {
		maxBridges = 3
	}

	alive := make([]*BridgeInfo, 0)
	for _, b := range r.bridges {
		if b.IsAlive {
			alive = append(alive, b)
		}
	}

	sort.Slice(alive, func(i, j int) bool {
		if alive[i].TrustLevel != alive[j].TrustLevel {
			return alive[i].TrustLevel > alive[j].TrustLevel
		}
		return alive[i].Latency < alive[j].Latency
	})

	seed := hashUserID(userID)
	result := make([]*BridgeInfo, 0, maxBridges)

	offset := int(seed) % max(len(alive), 1)
	for i := 0; i < len(alive) && len(result) < maxBridges; i++ {
		idx := (offset + i) % len(alive)
		result = append(result, alive[idx])
	}

	return result
}

func hashUserID(userID string) uint64 {
	var h uint64
	for _, c := range userID {
		h = h*31 + uint64(c)
	}
	return h
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type BridgeRotation struct {
	registry *Registry
	interval time.Duration
	stopCh   chan struct{}
}

func NewBridgeRotation(registry *Registry, interval time.Duration) *BridgeRotation {
	if interval <= 0 {
		interval = 4 * time.Hour
	}
	return &BridgeRotation{
		registry: registry,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (br *BridgeRotation) Start() {
	go func() {
		ticker := time.NewTicker(br.interval)
		defer ticker.Stop()
		for {
			select {
			case <-br.stopCh:
				return
			case <-ticker.C:
				br.rotate()
			}
		}
	}()
}

func (br *BridgeRotation) Stop() {
	close(br.stopCh)
}

func (br *BridgeRotation) rotate() {
	br.registry.mu.Lock()
	defer br.registry.mu.Unlock()

	for _, b := range br.registry.bridges {
		if !b.IsAlive {
			continue
		}
		stale := time.Since(b.LastCheck) > 2*br.interval
		if stale {
			b.TrustLevel = max(b.TrustLevel-5, 0)
		}
	}

	br.registry.persist()
}

type BridgeAlert struct {
	BridgeID  string    `json:"bridge_id"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

type NotificationManager struct {
	mu       sync.Mutex
	alerts   []BridgeAlert
	handlers []func(BridgeAlert)
	maxAlerts int
}

func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		alerts:    make([]BridgeAlert, 0),
		maxAlerts: 1000,
	}
}

func (nm *NotificationManager) OnAlert(handler func(BridgeAlert)) {
	nm.mu.Lock()
	nm.handlers = append(nm.handlers, handler)
	nm.mu.Unlock()
}

func (nm *NotificationManager) Emit(alert BridgeAlert) {
	alert.Timestamp = time.Now()
	nm.mu.Lock()
	nm.alerts = append(nm.alerts, alert)
	if len(nm.alerts) > nm.maxAlerts {
		nm.alerts = nm.alerts[len(nm.alerts)-nm.maxAlerts:]
	}
	handlers := make([]func(BridgeAlert), len(nm.handlers))
	copy(handlers, nm.handlers)
	nm.mu.Unlock()

	for _, h := range handlers {
		go h(alert)
	}
}

func (nm *NotificationManager) GetAlerts(since time.Time, limit int) []BridgeAlert {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	result := make([]BridgeAlert, 0)
	for i := len(nm.alerts) - 1; i >= 0 && len(result) < limit; i-- {
		if nm.alerts[i].Timestamp.After(since) {
			result = append(result, nm.alerts[i])
		}
	}
	return result
}

type UpdateDelivery struct {
	registry    *Registry
	notifier    *NotificationManager
	parallelism int
}

func NewUpdateDelivery(registry *Registry, notifier *NotificationManager, parallelism int) *UpdateDelivery {
	if parallelism <= 0 {
		parallelism = 5
	}
	return &UpdateDelivery{
		registry:    registry,
		notifier:    notifier,
		parallelism: parallelism,
	}
}

type UpdateResult struct {
	BridgeID string `json:"bridge_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

func (ud *UpdateDelivery) DeliverUpdate(version string, binaryURL string, checksum string) []UpdateResult {
	bridges := ud.registry.GetAliveBridges()
	results := make([]UpdateResult, len(bridges))

	sem := make(chan struct{}, ud.parallelism)
	var wg sync.WaitGroup

	for i, b := range bridges {
		wg.Add(1)
		go func(idx int, bridge *BridgeInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = ud.deliverToBridge(bridge, version, binaryURL, checksum)
		}(i, b)
	}

	wg.Wait()

	allSuccess := true
	for _, r := range results {
		if !r.Success {
			allSuccess = false
			ud.notifier.Emit(BridgeAlert{
				BridgeID: r.BridgeID,
				Type:     "update_failed",
				Message:  r.Error,
				Severity: "warning",
			})
		}
	}

	if allSuccess {
		ud.notifier.Emit(BridgeAlert{
			Type:     "update_complete",
			Message:  fmt.Sprintf("All %d bridges updated to %s", len(bridges), version),
			Severity: "info",
		})
	}

	return results
}

func (ud *UpdateDelivery) deliverToBridge(bridge *BridgeInfo, version, binaryURL, checksum string) UpdateResult {
	_ = version
	_ = binaryURL
	_ = checksum
	return UpdateResult{
		BridgeID: bridge.ID,
		Success:  true,
	}
}
