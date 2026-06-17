package db

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID         uuid.UUID `json:"id"`
	UserID     uuid.UUID `json:"user_id"`
	DeviceName string    `json:"device_name"`
	IPAddress  string    `json:"ip_address"`
	ServerID   string    `json:"server_id"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	StartedAt  time.Time `json:"started_at"`
	LastSeen   time.Time `json:"last_seen"`
}

func (db *DB) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, user_id, device_name, ip_address, server_id, bytes_in, bytes_out, started_at, last_seen
		FROM sessions WHERE user_id = $1 ORDER BY started_at DESC
	`, userID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.DeviceName, &s.IPAddress,
			&s.ServerID, &s.BytesIn, &s.BytesOut, &s.StartedAt, &s.LastSeen); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}

	return sessions, nil
}
