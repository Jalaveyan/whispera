package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserExists      = errors.New("user already exists")
	ErrInvalidPassword = errors.New("invalid password")
	ErrUserInactive    = errors.New("user is inactive")
)

type User struct {
	ID           uuid.UUID  `json:"id"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	PublicKey    *string    `json:"public_key,omitempty"`
	PlanID       *uuid.UUID `json:"plan_id,omitempty"`
	IsActive     bool       `json:"is_active"`
	IsAdmin      bool       `json:"is_admin"`
	TrafficUsed  int64      `json:"traffic_used"`
	ValidUntil   *time.Time `json:"valid_until,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`

	PlanName     string `json:"plan_name,omitempty"`
	TrafficLimit int64  `json:"traffic_limit"`
	SpeedLimit   int    `json:"speed_limit"`
	MaxDevices   int    `json:"max_devices"`

	ObfsProfile       string `json:"obfs_profile"`
	MarionetteProfile string `json:"marionette_profile"`
	RussianService    string `json:"russian_service"`
	PrivateKey        string `json:"private_key,omitempty"`
	TelegramID        *int64 `json:"telegram_id,omitempty"`
}

func (db *DB) CreateUser(ctx context.Context, email, password string, trafficLimit int64, validUntil *time.Time, obfsProfile, marionetteProfile, russianService, publicKey, privateKey string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var user User
	err = db.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, traffic_limit, valid_until, obfs_profile, marionette_profile, russian_service, public_key, private_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, email, is_active, is_admin, traffic_used, traffic_limit, valid_until, created_at, updated_at, obfs_profile, marionette_profile, russian_service, public_key, private_key
	`, email, string(hash), trafficLimit, validUntil, obfsProfile, marionetteProfile, russianService, publicKey, privateKey).Scan(
		&user.ID, &user.Email, &user.IsActive, &user.IsAdmin,
		&user.TrafficUsed, &user.TrafficLimit, &user.ValidUntil, &user.CreatedAt, &user.UpdatedAt,
		&user.ObfsProfile, &user.MarionetteProfile, &user.RussianService,
		&user.PublicKey, &user.PrivateKey,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrUserExists
		}
		return nil, err
	}

	return &user, nil
}

func (db *DB) UpdateUser(ctx context.Context, id uuid.UUID, email, password string) error {
	var query string
	var args []interface{}

	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		query = `UPDATE users SET email = $1, password_hash = $2, updated_at = NOW() WHERE id = $3`
		args = []interface{}{email, string(hash), id}
	} else {
		query = `UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2`
		args = []interface{}{email, id}
	}

	result, err := db.pool.Exec(ctx, query, args...)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrUserExists
		}
		return err
	}

	if result.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := db.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.password_hash, u.public_key, u.private_key, u.plan_id,
		       u.is_active, u.is_admin, u.traffic_used, u.valid_until,
		       u.created_at, u.updated_at,
		       COALESCE(p.name, 'Free') as plan_name,
		       COALESCE(p.traffic_limit, 0) as traffic_limit,
		       COALESCE(p.speed_limit, 0) as speed_limit,
		       COALESCE(p.max_devices, 1) as max_devices,
		       COALESCE(u.obfs_profile, 'http2'),
		       COALESCE(u.marionette_profile, 'browser'),
		       COALESCE(u.russian_service, 'vk'),
		       u.telegram_id
		FROM users u
		LEFT JOIN plans p ON u.plan_id = p.id
		WHERE u.email = $1
	`, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.PublicKey, &user.PrivateKey, &user.PlanID,
		&user.IsActive, &user.IsAdmin, &user.TrafficUsed, &user.ValidUntil,
		&user.CreatedAt, &user.UpdatedAt,
		&user.PlanName, &user.TrafficLimit, &user.SpeedLimit, &user.MaxDevices,
		&user.ObfsProfile, &user.MarionetteProfile, &user.RussianService,
		&user.TelegramID,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("query user by email: %w", err)
	}

	return &user, nil
}

func (db *DB) AuthenticateUser(ctx context.Context, email, password string) (*User, error) {
	user, err := db.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidPassword
	}

	return user, nil
}

func (db *DB) SetUserPublicKey(ctx context.Context, userID uuid.UUID, pubKey string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE users SET public_key = $1, updated_at = NOW() WHERE id = $2
	`, pubKey, userID)
	return err
}

func (db *DB) SetAdmin(ctx context.Context, userID uuid.UUID, isAdmin bool) error {
	_, err := db.pool.Exec(ctx, `UPDATE users SET is_admin = $1, updated_at = NOW() WHERE id = $2`, isAdmin, userID)
	return err
}

func (db *DB) ListUsers(ctx context.Context, limit, offset int) ([]User, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT u.id, u.email, u.public_key, u.private_key, u.plan_id,
		       u.is_active, u.is_admin, u.traffic_used, u.valid_until,
		       u.created_at, u.updated_at,
		       COALESCE(p.name, 'Free') as plan_name,
		       COALESCE(p.traffic_limit, 0) as traffic_limit,
		       COALESCE(p.speed_limit, 0) as speed_limit,
		       COALESCE(p.max_devices, 1) as max_devices,
		       COALESCE(u.obfs_profile, 'http2'),
		       COALESCE(u.marionette_profile, 'browser'),
		       COALESCE(u.russian_service, 'vk'),
		       u.telegram_id
		FROM users u
		LEFT JOIN plans p ON u.plan_id = p.id
		ORDER BY u.created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		err := rows.Scan(
			&u.ID, &u.Email, &u.PublicKey, &u.PrivateKey, &u.PlanID,
			&u.IsActive, &u.IsAdmin, &u.TrafficUsed, &u.ValidUntil,
			&u.CreatedAt, &u.UpdatedAt, &u.PlanName,
			&u.TrafficLimit, &u.SpeedLimit, &u.MaxDevices,
			&u.ObfsProfile, &u.MarionetteProfile, &u.RussianService,
			&u.TelegramID,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, nil
}

func (db *DB) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	result, err := db.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}
