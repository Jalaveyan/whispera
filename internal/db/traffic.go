package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type TrafficLog struct {
	ID        int64     `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	SessionID uuid.UUID `json:"session_id"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Duration  int       `json:"duration"`
	Timestamp time.Time `json:"timestamp"`
}

type DailyStats struct {
	Date     time.Time `json:"date"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	Sessions int       `json:"sessions"`
}

func (db *DB) LogTraffic(ctx context.Context, userID, sessionID uuid.UUID, bytesIn, bytesOut int64, duration int) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO traffic_logs (user_id, session_id, bytes_in, bytes_out, duration)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, sessionID, bytesIn, bytesOut, duration)
	if err != nil {
		return fmt.Errorf("insert traffic log: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE users SET traffic_used = traffic_used + $1, updated_at = NOW() WHERE id = $2
	`, bytesIn+bytesOut, userID)
	if err != nil {
		return fmt.Errorf("update traffic used: %w", err)
	}

	return tx.Commit(ctx)
}

func (db *DB) UpdateDailyStats(ctx context.Context, userID uuid.UUID, bytesIn, bytesOut int64) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO daily_stats (date, user_id, bytes_in, bytes_out, sessions)
		VALUES (CURRENT_DATE, $1, $2, $3, 1)
		ON CONFLICT (date, user_id) DO UPDATE SET
			bytes_in = daily_stats.bytes_in + $2,
			bytes_out = daily_stats.bytes_out + $3,
			sessions = daily_stats.sessions + 1
	`, userID, bytesIn, bytesOut)
	return err
}

func (db *DB) GetUserDailyStats(ctx context.Context, userID uuid.UUID, days int) ([]DailyStats, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT date, bytes_in, bytes_out, sessions
		FROM daily_stats
		WHERE user_id = $1 AND date >= CURRENT_DATE - $2::int
		ORDER BY date DESC
	`, userID, days)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []DailyStats
	for rows.Next() {
		var s DailyStats
		if err := rows.Scan(&s.Date, &s.BytesIn, &s.BytesOut, &s.Sessions); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}

	return stats, nil
}

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

func (db *DB) CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	result, err := db.pool.Exec(ctx,
		`DELETE FROM traffic_logs WHERE timestamp < NOW() - ($1 * INTERVAL '1 day')`,
		retentionDays,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
