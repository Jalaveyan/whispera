package apiserver

import (
	"encoding/json"
	"net/http"
)

// handleBridgeStats возвращает сводную статистику по всем мостам:
// total / alive / dead / avg_latency.
func (s *Server) handleBridgeStats(w http.ResponseWriter, r *http.Request) {
	s.jsonOK(w, s.bridgePool.BridgeStats())
}

// handleBridgeCheck запускает немедленную проверку доступности конкретного моста.
// Тело запроса: {"id": "<bridge_id>"}
// Возвращает обновлённые is_alive и latency_ms.
func (s *Server) handleBridgeCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		s.jsonError(w, http.StatusBadRequest, "id required")
		return
	}

	isAlive, latency, err := s.bridgePool.CheckBridgeNow(req.ID)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"id":         req.ID,
		"is_alive":   isAlive,
		"latency_ms": latency,
	})
}
