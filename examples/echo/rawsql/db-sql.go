package rawsql

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type PGUser struct {
	Id        uuid.UUID
	Name      string
	Email     string
	CreatedAt time.Time
}

type PGUserCredentials struct {
	Id           uuid.UUID
	UserId       uuid.UUID
	PasswordHash []byte
	Salt         string
	CreatedAt    time.Time
}

type PGOAuthUserAccount struct {
	Id             uuid.UUID
	UserId         uuid.UUID
	ProviderId     string
	ProviderUserId string
	CreatedAt      time.Time
}

type PGOAuthProvder struct {
	Id        uuid.UUID
	Name      string
	CreatedAt time.Time
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
	stmt := ` INSERT INTO users (
            name,
            email
            )
            VALUES ($1, $2)
            RETURNING id, name, email
          `
	err := db.QueryRow(
		stmt, u.Name,
		u.Email,
	).Scan(
		&user.Id,
		&user.Name,
		&user.Email,
	)
	if err != nil {
		return user, fmt.Errorf("Unable to insert new user in users table, err: %w", err)
	}

	return user, nil
}

func InsertUserCredentials(db *sql.DB, uc *PGUserCredentials) error {
	stmt := ` INSERT INTO user_credentials (
            user_id,
            password_hash,
            salt
            )
            VALUES ($1, $2, $3)
          `
	_, err := db.Exec(stmt, uc.UserId, uc.PasswordHash, uc.Salt)
	if err != nil {
		return fmt.Errorf("unable to insert user credentials: %w", err)
	}
	return nil
}

func InsertOAuthUserAccount(db *sql.DB, oa *PGOAuthUserAccount) error {
	account := PGOAuthUserAccount{}
	stmt := ` INSERT INTO user_oauth_accounts (
              user_id,
              provider_id,
              provider_user_id
              )
              VALUES ($1, $2, $3)
              RETURNING id, user_id, provider_id, provider_user_id, created_at
            `
	err := db.QueryRow(
		stmt,
		oa.UserId,
		oa.ProviderId,
		oa.ProviderUserId,
	).Scan(
		&account.Id,
		&account.UserId,
		&account.ProviderId,
		&account.ProviderUserId,
		&account.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("unable to insert new OAuth user account: %w", err)
	}

	return nil
}

func InsertSession(db *sql.DB, s *PGSession) error {
	stmt := ` INSERT INTO user_sessions (
            id,
            user_id, 
            expiry_date, 
            last_seen_time
            )
            VALUES ($1, $2, $3, $4)
          `
	_, err := db.Exec(stmt, s.Id, s.UserId, s.ExpiryDate, s.LastSeenTime)

	return err
}

func UpdateSession(db *sql.DB, s *PGSession) error {
	stmt := ` UPDATE user_sessions 
            SET last_seen_time=$1, expiry_date=$2 
            WHERE id=$3
          `
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
            FROM user_sessions WHERE id = $1
          `
	err := db.QueryRow(stmt, sessionId).Scan(&s.Id, &s.UserId, &s.ExpiryDate, &s.LastSeenTime, &s.LogInTime)
	if err != nil {
		return s, fmt.Errorf("Unable to find session in the database, err: %w", err)
	}

	return s, nil
}

func SelectOneUserByEmail(db *sql.DB, email string) (PGUser, error) {
	u := PGUser{}

	stmt := ` SELECT id, name, email
            FROM users 
            WHERE email = $1
          `
	err := db.QueryRow(stmt, email).Scan(&u.Id, &u.Name, &u.Email)
	if err != nil {
		return u, fmt.Errorf("Unable to find user in the database, err: %w", err)
	}

	return u, nil
}

func SelectUserCredentialsByUserId(db *sql.DB, userId uuid.UUID) (PGUserCredentials, error) {
	uc := PGUserCredentials{}
	stmt := `
    SELECT id, user_id, password_hash, salt, created_at
    FROM user_credentials 
    WHERE user_id = $1
    `
	err := db.QueryRow(stmt, userId).Scan(
		&uc.Id, &uc.UserId, &uc.PasswordHash, &uc.Salt, &uc.CreatedAt,
	)
	if err != nil {
		return uc, fmt.Errorf("unable to find user credentials in the database: %w", err)
	}
	return uc, nil
}

func SelectOAuthUserAccountByProviderIdAndUserId(db *sql.DB, providerId, userId string) (PGOAuthUserAccount, error) {
	account := PGOAuthUserAccount{}
	stmt := ` SELECT 
              id,
              user_id,
              provider_id,
              provider_user_id,
              created_at
              FROM user_oauth_accounts
              WHERE provider_id = $1 AND user_id = $2
            `
	err := db.QueryRow(stmt, providerId, userId).Scan(
		&account.Id,
		&account.UserId,
		&account.ProviderId,
		&account.ProviderUserId,
		&account.CreatedAt,
	)
	if err != nil {
		return account, fmt.Errorf("unable to find OAuth user account: %w", err)
	}

	return account, nil
}

func SelectOAuthUserAccountsByUserId(db *sql.DB, userId uuid.UUID) ([]PGOAuthUserAccount, error) {
	stmt := ` SELECT id,
              user_id,
              provider_id,
              provider_user_id,
              created_at
              FROM user_oauth_accounts
              WHERE user_id = $1
            `
	rows, err := db.Query(stmt, userId)
	if err != nil {
		return nil, fmt.Errorf("unable to query OAuth user accounts: %w", err)
	}
	defer rows.Close()

	var accounts []PGOAuthUserAccount
	for rows.Next() {
		var account PGOAuthUserAccount
		err := rows.Scan(
			&account.Id,
			&account.UserId,
			&account.ProviderId,
			&account.ProviderUserId,
			&account.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to scan OAuth user account: %w", err)
		}
		accounts = append(accounts, account)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating OAuth user accounts: %w", err)
	}

	return accounts, nil
}

func CreateUserTable(db *sql.DB) error {
	stmt := ` CREATE TABLE IF NOT EXISTS users (
            id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE("name"),
	          UNIQUE("email")
            );`
	_, err := db.Exec(stmt)
	if err != nil {
		return fmt.Errorf("Unable to create users table in the database, err: %w", err)
	}
	return nil
}

func CreateUserCredentialsTable(db *sql.DB) error {
	stmt := ` CREATE TABLE IF NOT EXISTS user_credentials (
            id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
            password_hash BYTEA NOT NULL,
            salt VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE
            );`
	_, err := db.Exec(stmt)
	if err != nil {
		return fmt.Errorf("Unable to create user_credentials table in the database, err: %w", err)
	}

	return nil
}

func CreateUserOauthAccountsTable(db *sql.DB) error {
	stmt := ` CREATE TABLE IF NOT EXISTS user_oauth_accounts (
            id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            provider_id VARCHAR(255) REFERENCES oauth_providers(id),
            provider_user_id VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(provider_id, provider_user_id),
            UNIQUE(provider_id, user_id)
            );`
	_, err := db.Exec(stmt)
	if err != nil {
		return fmt.Errorf("Unable to create user_oauth_accounts table in the database, err: %w", err)
	}
	return nil
}

func CreateOauthProviderTable(db *sql.DB) error {
	stmt := ` CREATE TABLE IF NOT EXISTS oauth_providers (
            id VARCHAR(255) NOT NULL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );`
	_, err := db.Exec(stmt)
	if err != nil {
		return fmt.Errorf("Unable to create oauth_providers table in the database, err: %w", err)
	}
	err = SeedOauthProviderTable(db)
	if err != nil {
		return err
	}

	return nil
}

func CreateSessionTable(db *sql.DB) error {
	stmt := ` CREATE TABLE IF NOT EXISTS user_sessions (
            id VARCHAR(255) PRIMARY KEY NOT NULL UNIQUE,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expiry_date TIMESTAMPTZ NOT NULL,
            last_seen_time TIMESTAMPTZ NOT NULL,
            log_in_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );`
	_, err := db.Exec(stmt)
	if err != nil {
		return fmt.Errorf("Unable to create users_sessions table in the database, err: %w", err)
	}
	return nil
}

func SeedOauthProviderTable(db *sql.DB) error {
	// First, check if the table is empty
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM oauth_providers").Scan(&count)
	if err != nil {
		return fmt.Errorf("error checking oauth_providers table: %w", err)
	}

	// If the table is not empty, return without seeding
	if count > 0 {
		return nil
	}

	stmt := ` INSERT INTO oauth_providers 
            (id,
            name
            )
            VALUES ($1, $2)
            ON CONFLICT (name) DO NOTHING
            `
	_, err = db.Exec(stmt, "google", "Google")
	if err != nil {
		return fmt.Errorf("Unable to seed database, err: %w", err)
	}
	return nil
}
