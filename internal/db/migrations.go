package db

import (
	"context"
	"fmt"
	"log"
)

type migration struct {
	Version     int
	Description string
	SQL         string
}

func allMigrations() []migration {
	return []migration{
		{1, "Create plans table", `CREATE TABLE IF NOT EXISTS plans (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            VARCHAR(100) NOT NULL UNIQUE,
			traffic_limit   BIGINT DEFAULT 0,
			speed_limit     INT DEFAULT 0,
			max_devices     INT DEFAULT 1,
			price_monthly   DECIMAL(10,2) DEFAULT 0,
			features        JSONB DEFAULT '{}',
			created_at      TIMESTAMP DEFAULT NOW()
		)`},

		{2, "Create users table", `CREATE TABLE IF NOT EXISTS users (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			email           VARCHAR(255) UNIQUE NOT NULL,
			password_hash   VARCHAR(255) NOT NULL,
			public_key      VARCHAR(64) UNIQUE,
			plan_id         UUID REFERENCES plans(id),
			is_active       BOOLEAN DEFAULT TRUE,
			is_admin        BOOLEAN DEFAULT FALSE,
			traffic_used    BIGINT DEFAULT 0,
			valid_until     TIMESTAMP,
			created_at      TIMESTAMP DEFAULT NOW(),
			updated_at      TIMESTAMP DEFAULT NOW()
		)`},

		{3, "Create sessions table", `CREATE TABLE IF NOT EXISTS sessions (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
			device_name     VARCHAR(255),
			ip_address      INET,
			server_id       VARCHAR(100),
			bytes_in        BIGINT DEFAULT 0,
			bytes_out       BIGINT DEFAULT 0,
			started_at      TIMESTAMP DEFAULT NOW(),
			last_seen       TIMESTAMP DEFAULT NOW()
		)`},

		{4, "Create traffic_logs table", `CREATE TABLE IF NOT EXISTS traffic_logs (
			id              BIGSERIAL PRIMARY KEY,
			user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
			session_id      UUID,
			bytes_in        BIGINT DEFAULT 0,
			bytes_out       BIGINT DEFAULT 0,
			duration        INT DEFAULT 0,
			timestamp       TIMESTAMP DEFAULT NOW()
		)`},

		{5, "Create daily_stats table", `CREATE TABLE IF NOT EXISTS daily_stats (
			date            DATE NOT NULL,
			user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
			bytes_in        BIGINT DEFAULT 0,
			bytes_out       BIGINT DEFAULT 0,
			sessions        INT DEFAULT 0,
			PRIMARY KEY (date, user_id)
		)`},

		{6, "Create indexes", `
			CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
			CREATE INDEX IF NOT EXISTS idx_users_pubkey ON users(public_key);
			CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
			CREATE INDEX IF NOT EXISTS idx_traffic_user_time ON traffic_logs(user_id, timestamp)
		`},

		{7, "Seed default plans", `
			INSERT INTO plans (name, traffic_limit, speed_limit, max_devices, features)
			 VALUES ('Free', 10737418240, 50, 1, '{"priority": false}')
			 ON CONFLICT (name) DO NOTHING;
			INSERT INTO plans (name, traffic_limit, speed_limit, max_devices, price_monthly, features)
			 VALUES ('Pro', 107374182400, 200, 3, 9.99, '{"priority": true}')
			 ON CONFLICT (name) DO NOTHING;
			INSERT INTO plans (name, traffic_limit, speed_limit, max_devices, price_monthly, features)
			 VALUES ('Unlimited', 0, 0, 10, 19.99, '{"priority": true, "dedicated_ip": true}')
			 ON CONFLICT (name) DO NOTHING
		`},

		{8, "Add user profile columns", `
			ALTER TABLE users ADD COLUMN IF NOT EXISTS traffic_limit BIGINT DEFAULT 0;
			ALTER TABLE users ADD COLUMN IF NOT EXISTS obfs_profile VARCHAR(50) DEFAULT 'http2';
			ALTER TABLE users ADD COLUMN IF NOT EXISTS marionette_profile VARCHAR(50) DEFAULT 'browser';
			ALTER TABLE users ADD COLUMN IF NOT EXISTS russian_service VARCHAR(50) DEFAULT 'vk';
			ALTER TABLE users ADD COLUMN IF NOT EXISTS private_key VARCHAR(64);
			ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_id BIGINT UNIQUE
		`},
	}
}

func (db *DB) Migrate(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INT PRIMARY KEY,
			description VARCHAR(255) NOT NULL,
			applied_at  TIMESTAMP DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	var currentVersion int
	err = db.pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("get current migration version: %w", err)
	}

	migrations := allMigrations()
	applied := 0

	for _, m := range migrations {
		if m.Version <= currentVersion {
			continue
		}


		tx, err := db.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin transaction for migration %d: %w", m.Version, err)
		}

		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migration %d (%s) failed: %w", m.Version, m.Description, err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, description) VALUES ($1, $2)`, m.Version, m.Description); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("record migration %d: %w", m.Version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.Version, err)
		}

		applied++
	}

	if applied > 0 {
		log.Printf("[DB] Applied %d migrations (current version: %d)", applied, migrations[len(migrations)-1].Version)
	} else {
		log.Printf("[DB] Migrations up to date (version: %d)", currentVersion)
	}

	return nil
}
