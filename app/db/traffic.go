package db

import (
	"context"

	"github.com/google/uuid"
)

type TotalStats struct {
	TotalBytesIn  int64 `json:"total_bytes_in"`
	TotalBytesOut int64 `json:"total_bytes_out"`
	TotalSessions int   `json:"total_sessions"`
	ActiveNow     int   `json:"active_now"`
}

func (db *DB) GetUserTotalStats(ctx context.Context, userID uuid.UUID) (*TotalStats, error) {
	var stats TotalStats

	_ = db.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0), COALESCE(SUM(sessions), 0)
		FROM daily_stats WHERE user_id = $1
	`, userID).Scan(&stats.TotalBytesIn, &stats.TotalBytesOut, &stats.TotalSessions)

	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = $1`, userID).Scan(&stats.ActiveNow)

	return &stats, nil
}
