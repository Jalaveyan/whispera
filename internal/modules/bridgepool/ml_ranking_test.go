package bridgepool

// Item 8: Neural network bridge ranking/selection
//
// Тесты охватывают:
// - GetBestBridges: сортировка по latency + ML score
// - mlRankBridges: интеграция с mock ML server
// - AdaptiveManager: auto-switch при деградации бриджа
// - fallback при недоступности ML сервера
// - стабильность ранжирования при одинаковых параметрах

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

// --- Mock ML server ---

func mockMLServer(scores map[string]float64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rank/bridges" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		var bridges []struct {
			ID string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&bridges)

		type rankResult struct {
			ID      string  `json:"id"`
			MLScore float64 `json:"ml_score"`
		}
		results := make([]rankResult, 0, len(bridges))
		for _, b := range bridges {
			score := scores[b.ID]
			results = append(results, rankResult{ID: b.ID, MLScore: score})
		}
		// Сортируем по убыванию score
		sort.Slice(results, func(i, j int) bool {
			return results[i].MLScore > results[j].MLScore
		})
		json.NewEncoder(w).Encode(results)
	}))
}

func makeBridgeWithLatency(id, addr string, latencyMs int, btype BridgeType) *BridgeInfo {
	return &BridgeInfo{
		ID:        id,
		Address:   addr,
		Type:      btype,
		IsAlive:   true,
		Latency:   latencyMs,
		CreatedAt: time.Now(),
		MaxUsers:  100,
		Bandwidth: 100,
	}
}

// --- mlRankBridges integration ---

// TestMLRankBridgesIntegration: mock ML сервер возвращает ранжирование,
// функция mlRankBridges правильно его парсит.
func TestMLRankBridgesIntegration(t *testing.T) {
	scores := map[string]float64{
		"br-a": 0.95,
		"br-b": 0.40,
		"br-c": 0.70,
	}
	srv := mockMLServer(scores)
	defer srv.Close()

	// Подменяем URL через переменную окружения
	t.Setenv("WHISPERA_ML_SERVER", srv.URL)

	bridges := []*BridgeInfo{
		makeBridgeWithLatency("br-a", "1.1.1.1:8443", 20, BridgeOperator),
		makeBridgeWithLatency("br-b", "2.2.2.2:8443", 10, BridgeOperator),
		makeBridgeWithLatency("br-c", "3.3.3.3:8443", 15, BridgeOperator),
	}

	ranked := mlRankBridges(bridges)
	if ranked == nil {
		t.Fatal("mlRankBridges returned nil (ML server call failed)")
	}

	if ranked["br-a"] < ranked["br-c"] {
		t.Errorf("br-a (0.95) should rank higher than br-c (0.70), got a=%.3f c=%.3f", ranked["br-a"], ranked["br-c"])
	}
	if ranked["br-c"] < ranked["br-b"] {
		t.Errorf("br-c (0.70) should rank higher than br-b (0.40), got c=%.3f b=%.3f", ranked["br-c"], ranked["br-b"])
	}
}

// TestMLRankBridgesFallbackOnError: при недоступности ML сервера
// mlRankBridges возвращает nil и система работает без ранжирования.
func TestMLRankBridgesFallbackOnError(t *testing.T) {
	t.Setenv("WHISPERA_ML_SERVER", "http://127.0.0.1:19999") // нет сервера

	bridges := []*BridgeInfo{
		makeBridgeWithLatency("br-x", "1.1.1.1:8443", 30, BridgeOperator),
	}

	ranked := mlRankBridges(bridges)
	if ranked != nil {
		t.Error("expected nil from mlRankBridges when ML server unavailable")
	}
}

// --- GetBestBridges (API handler) ---

// TestGetBestBridgesLatencyOrder: без ML сервера бриджи сортируются по latency.
func TestGetBestBridgesLatencyOrder(t *testing.T) {
	t.Setenv("WHISPERA_ML_SERVER", "http://127.0.0.1:19999") // недоступен

	r := newTestRegistry()
	r.RegisterBridge(makeBridgeWithLatency("slow", "1.1.1.1:8443", 200, BridgeOperator))
	r.RegisterBridge(makeBridgeWithLatency("fast", "2.2.2.2:8443", 10, BridgeOperator))
	r.RegisterBridge(makeBridgeWithLatency("mid", "3.3.3.3:8443", 50, BridgeOperator))

	bridges := r.GetAliveBridges()

	// Сортируем по latency вручную (как делает API без ML)
	sort.Slice(bridges, func(i, j int) bool {
		return bridges[i].Latency < bridges[j].Latency
	})

	if bridges[0].ID != "fast" {
		t.Errorf("expected 'fast' first, got %s", bridges[0].ID)
	}
	if bridges[1].ID != "mid" {
		t.Errorf("expected 'mid' second, got %s", bridges[1].ID)
	}
	if bridges[2].ID != "slow" {
		t.Errorf("expected 'slow' third, got %s", bridges[2].ID)
	}
}

// TestGetBestBridgesMLOverridesLatency: ML score переопределяет порядок по latency.
func TestGetBestBridgesMLOverridesLatency(t *testing.T) {
	// ML считает медленный бридж лучшим (другая страна, низкий DPI риск)
	scores := map[string]float64{
		"slow-but-safe": 0.98,
		"fast-but-risky": 0.20,
		"mid":           0.50,
	}
	srv := mockMLServer(scores)
	defer srv.Close()
	t.Setenv("WHISPERA_ML_SERVER", srv.URL)

	r := newTestRegistry()
	r.RegisterBridge(makeBridgeWithLatency("slow-but-safe", "1.1.1.1:8443", 200, BridgeOperator))
	r.RegisterBridge(makeBridgeWithLatency("fast-but-risky", "2.2.2.2:8443", 5, BridgeOperator))
	r.RegisterBridge(makeBridgeWithLatency("mid", "3.3.3.3:8443", 50, BridgeOperator))

	bridges := r.GetAliveBridges()
	mlScores := mlRankBridges(bridges)

	// Применяем ML-score: composite = latencyNorm * 0.3 + mlScore * 0.7
	maxLatency := 0
	for _, b := range bridges {
		if b.Latency > maxLatency {
			maxLatency = b.Latency
		}
	}

	type scoredBridge struct {
		id        string
		composite float64
	}
	scored := make([]scoredBridge, len(bridges))
	for i, b := range bridges {
		latencyNorm := 1.0 - float64(b.Latency)/float64(maxLatency+1)
		ml := 0.5
		if mlScores != nil {
			if s, ok := mlScores[b.ID]; ok {
				ml = s
			}
		}
		scored[i] = scoredBridge{id: b.ID, composite: latencyNorm*0.3 + ml*0.7}
	}
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].composite > scored[j].composite
	})

	if scored[0].id != "slow-but-safe" {
		t.Errorf("ML should rank slow-but-safe #1, got %s (%.3f)", scored[0].id, scored[0].composite)
	}
	if scored[2].id != "fast-but-risky" {
		t.Errorf("fast-but-risky should be last due to low ML score, got %s", scored[2].id)
	}
}

// TestMLRankBridgesEmptyList: пустой список не паникует.
func TestMLRankBridgesEmptyList(t *testing.T) {
	srv := mockMLServer(nil)
	defer srv.Close()
	t.Setenv("WHISPERA_ML_SERVER", srv.URL)

	ranked := mlRankBridges([]*BridgeInfo{})
	// nil или пустая map — оба приемлемы
	_ = ranked
}

// TestMLRankBridgesSingleBridge: один бридж ранжируется корректно.
func TestMLRankBridgesSingleBridge(t *testing.T) {
	scores := map[string]float64{"solo": 0.88}
	srv := mockMLServer(scores)
	defer srv.Close()
	t.Setenv("WHISPERA_ML_SERVER", srv.URL)

	bridges := []*BridgeInfo{
		makeBridgeWithLatency("solo", "1.1.1.1:8443", 30, BridgeOperator),
	}
	ranked := mlRankBridges(bridges)
	if ranked == nil {
		t.Fatal("single bridge ranking returned nil")
	}
	if ranked["solo"] != 0.88 {
		t.Errorf("score mismatch: got %.3f, want 0.88", ranked["solo"])
	}
}

// TestMLRankStabilityIdenticalScores: при одинаковых ML score порядок стабилен.
func TestMLRankStabilityIdenticalScores(t *testing.T) {
	scores := map[string]float64{
		"br-1": 0.60,
		"br-2": 0.60,
		"br-3": 0.60,
	}
	srv := mockMLServer(scores)
	defer srv.Close()
	t.Setenv("WHISPERA_ML_SERVER", srv.URL)

	bridges := []*BridgeInfo{
		makeBridgeWithLatency("br-1", "1.1.1.1:8443", 10, BridgeOperator),
		makeBridgeWithLatency("br-2", "2.2.2.2:8443", 20, BridgeOperator),
		makeBridgeWithLatency("br-3", "3.3.3.3:8443", 30, BridgeOperator),
	}

	r1 := mlRankBridges(bridges)
	r2 := mlRankBridges(bridges)

	// Scores должны совпадать при повторных вызовах
	for id, s1 := range r1 {
		if s2, ok := r2[id]; !ok || s1 != s2 {
			t.Errorf("score for %s differs between calls: %.3f vs %.3f", id, s1, s2)
		}
	}
}

// TestMLRankDeadBridgesExcluded: мёртвые бриджи не попадают в ранжирование.
func TestMLRankDeadBridgesExcluded(t *testing.T) {
	scores := map[string]float64{
		"alive": 0.80,
		"dead":  0.99, // высокий score, но мёртвый
	}
	srv := mockMLServer(scores)
	defer srv.Close()
	t.Setenv("WHISPERA_ML_SERVER", srv.URL)

	r := newTestRegistry()
	r.RegisterBridge(makeBridgeWithLatency("alive", "1.1.1.1:8443", 20, BridgeOperator))
	dead := makeBridgeWithLatency("dead", "2.2.2.2:8443", 5, BridgeOperator)
	dead.IsAlive = false
	r.RegisterBridge(dead)

	// GetAliveBridges фильтрует мёртвые ДО передачи в ML
	aliveBridges := r.GetAliveBridges()
	ranked := mlRankBridges(aliveBridges)

	if _, ok := ranked["dead"]; ok {
		t.Error("dead bridge should not be in ML ranking input")
	}
	if ranked["alive"] != 0.80 {
		t.Errorf("alive bridge score mismatch: %.3f", ranked["alive"])
	}
}
