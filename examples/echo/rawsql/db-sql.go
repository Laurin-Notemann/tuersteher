package rawsql

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type PGUser struct {
	Id             uuid.UUID
	Username       string
	Email          string
	HashedPassword []byte
	Salt           string
}

type PGSession struct {
	Id           string
	UserId       uuid.UUID
	ExpiryDate   time.Time
	LastSeenTime time.Time
	LogInTime    time.Time
}

func InsertUser(db *sql.DB, u *PGUser) (PGUser, error) {
	user := PGUser{}
	stmt := ` INSERT INTO users 
            (username,
            email,
            hashed_password,
            salt)
            VALUES ($1, $2, $3, $4)
            RETURNING id, username, email, hashed_password, salt
            `
	err := db.QueryRow(
		stmt, u.Username,
		u.Email,
		u.HashedPassword,
		u.Salt,
	).Scan(
		&user.Id,
		&user.Username,
		&user.Email,
		&user.HashedPassword,
		&user.Salt,
	)
	if err != nil {
		return user, fmt.Errorf("Unable to insert new user in users table, err: %w", err)
	}

	return user, nil
}

func InsertSession(db *sql.DB, s *PGSession) error {
	stmt := ` INSERT INTO user_sessions 
            (id,
            user_id, 
            expiry_date, 
            last_seen_time)
            VALUES ($1, $2, $3, $4)`
	_, err := db.Exec(stmt, s.Id, s.UserId, s.ExpiryDate, s.LastSeenTime)

	return err
}

func UpdateSession(db *sql.DB, s *PGSession) error {
	stmt := `UPDATE user_sessions SET last_seen_time=$1, expiry_date=$2 WHERE id=$3`
	_, err := db.Exec(stmt, s.LastSeenTime, s.ExpiryDate, s.Id)

	return err

}

func DeleteSession(db *sql.DB, s *PGSession) error {
	_, err := db.Exec("DELETE FROM user_sessions WHERE id = $1", s.Id)
	return err
}

func SelectOneSessionById(db *sql.DB, sessionId string) (PGSession, error) {
	s := PGSession{}

	stmt := ` SELECT 
            id,
            user_id,
            expiry_date,
            last_seen_time,
            log_in_time
            FROM user_sessions WHERE id = $1`
	err := db.QueryRow(stmt, sessionId).Scan(&s.Id, &s.UserId, &s.ExpiryDate, &s.LastSeenTime, &s.LogInTime)
	if err != nil {
		return s, fmt.Errorf("Unable to find session in the database, err: %w", err)
	}

	return s, nil
}

func SelectOneUserByEmail(db *sql.DB, email string) (PGUser, error) {
	u := PGUser{}

	stmt := ` SELECT 
            id,
            username,
            email,
            hashed_password,
            salt
            FROM users WHERE email = $1`
	err := db.QueryRow(stmt, email).Scan(&u.Id, &u.Username, &u.Email, &u.HashedPassword, &u.Salt)
	if err != nil {
		return u, fmt.Errorf("Unable to find session in the database, err: %w", err)
	}

	return u, nil
}

func CreateUserTable(db *sql.DB) error {
	stmt := `DO $$
              BEGIN
              CREATE TABLE IF NOT EXISTS users (
              id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
              username VARCHAR(255) NOT NULL,
              email VARCHAR(255) NOT NULL,
              hashed_password BYTEA NOT NULL,
              salt VARCHAR(255) NOT NULL,
              CONSTRAINT "users_username_unique" UNIQUE("username"),
	            CONSTRAINT "users_email_unique" UNIQUE("email")
              );
              EXCEPTION WHEN insufficient_privilege THEN
                IF NOT EXISTS (SELECT FROM pg_catalog.pg_tables WHERE schemaname = current_schema() AND tablename = 'users') THEN
                  RAISE;
                END IF;
              WHEN others THEN RAISE;
            END;
            $$;`
	_, err := db.Exec(stmt)
	if err != nil {
		return fmt.Errorf("Unable to create users table in the database, err: %w", err)
	}
	return nil
}

func CreateSessionTable(db *sql.DB) error {
	stmt := `DO $$
              BEGIN
              CREATE TABLE IF NOT EXISTS user_sessions (
              id VARCHAR(255) PRIMARY KEY NOT NULL UNIQUE,
              user_id uuid NOT NULL,
              expiry_date TIMESTAMPTZ NOT NULL,
              last_seen_time TIMESTAMPTZ NOT NULL,
              log_in_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
              CONSTRAINT "FK_User_sessions.user_id" FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
              );
              CREATE INDEX IF NOT EXISTS users_sessions_expiry_idx ON user_sessions (expiry_date);
              EXCEPTION WHEN insufficient_privilege THEN
                IF NOT EXISTS (SELECT FROM pg_catalog.pg_tables WHERE schemaname = current_schema() AND tablename = 'user_sessions') THEN
                  RAISE;
                END IF;
              WHEN others THEN RAISE;
            END;
            $$;`
	_, err := db.Exec(stmt)
	if err != nil {
		return fmt.Errorf("Unable to create users_sessions table in the database, err: %w", err)
	}
	return nil
}
