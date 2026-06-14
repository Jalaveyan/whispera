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

func (db *DB) CreateSession(ctx context.Context, userID uuid.UUID, deviceName, ipAddr, serverID string) (*Session, error) {
	var session Session
	err := db.pool.QueryRow(ctx, `
		INSERT INTO sessions (user_id, device_name, ip_address, server_id)
		VALUES ($1, $2, $3::inet, $4)
		RETURNING id, user_id, device_name, ip_address, server_id, bytes_in, bytes_out, started_at, last_seen
	`, userID, deviceName, ipAddr, serverID).Scan(
		&session.ID, &session.UserID, &session.DeviceName, &session.IPAddress,
		&session.ServerID, &session.BytesIn, &session.BytesOut, &session.StartedAt, &session.LastSeen,
	)

	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (db *DB) UpdateSessionTraffic(ctx context.Context, sessionID uuid.UUID, bytesIn, bytesOut int64) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE sessions 
		SET bytes_in = bytes_in + $1, bytes_out = bytes_out + $2, last_seen = NOW()
		WHERE id = $3
	`, bytesIn, bytesOut, sessionID)
	return err
}

func (db *DB) TouchSession(ctx context.Context, sessionID uuid.UUID) error {
	_, err := db.pool.Exec(ctx, `UPDATE sessions SET last_seen = NOW() WHERE id = $1`, sessionID)
	return err
}

func (db *DB) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	_, err := db.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	return err
}

func (db *DB) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := db.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
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

func (db *DB) CountUserSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	err := db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = $1`, userID).Scan(&count)
	return count, err
}

func (db *DB) CleanupStaleSessions(ctx context.Context) (int64, error) {
	result, err := db.pool.Exec(ctx, `
		DELETE FROM sessions WHERE last_seen < NOW() - INTERVAL '5 minutes'
	`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
