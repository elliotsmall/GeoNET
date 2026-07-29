package store

import (
	"context"

	"fmt"
	"log"

	"time"

	"github.com/google/uuid"
)

type User struct {
	UserID   uuid.UUID
	Username string
	Email    string
	Pass     string
	Role     string
	IsActive bool
}

func (store *Store) LookupByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{}

	err := store.pool.QueryRow(ctx,
		`SELECT user_id, username, email, pass, role, is_active
		FROM user_auth
		WHERE username = $1`, username).Scan(
		&user.UserID,
		&user.Username,
		&user.Email,
		&user.Pass,
		&user.Role,
		&user.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (store *Store) LookupByUUID(ctx context.Context, userID uuid.UUID) (*User, error) {
	user := &User{}

	err := store.pool.QueryRow(ctx,
		`SELECT user_id, username, email, role, is_active
		FROM user_auth
		WHERE username = $1`, userID).Scan(
		&user.UserID,
		&user.Username,
		&user.Email,
		&user.Role,
		&user.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (store *Store) CreateUser(ctx context.Context, userid uuid.UUID, username, email, pass, role string) error {
	_, err := store.pool.Exec(ctx,
		`INSERT INTO user_auth (user_id, username, email, pass, role, is_active)
		VALUES ($1, $2, $3, $4, $5, 1)`,
		userid, username, email, pass, role)
	if err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}
	log.Printf("user successfully inserted: %s", username)
	return nil
}

func (store *Store) SetUserSession(ctx context.Context, userID uuid.UUID, token []byte, expires time.Time) error {
	_, err := store.pool.Exec(ctx,
		`UPDATE user_auth
		SET session_token = $1, session_expires = $2
		WHERE user_id = $3 AND is_active = true`,
		token, expires, userID)
	if err != nil {
		return fmt.Errorf("setting session token: %w", err)
	}
	log.Printf("user session set")
	return nil
}

func (store *Store) ClearUserSession(ctx context.Context, userID uuid.UUID, username string) error {
	_, err := store.pool.Exec(ctx,
		`UPDATE user_auth
		SET session_token = NULL, session_expires = NULL
		WHERE user_id = $1`,
		userID)
	if err != nil {
		return fmt.Errorf("clearing session token: %w", err)
	}
	log.Printf("user session cleared: %s", username)
	return nil
}

func (store *Store) GetUserBySession(ctx context.Context, token []byte) (*User, error) {
	user := &User{}
	err := store.pool.QueryRow(ctx,
		`SELECT user_id, username, email, pass, role, is_active
		FROM user_auth
		WHERE session_token = $1
		AND session_expiration > now()
		AND is_active = true`,
		token).Scan(
		&user.UserID,
		&user.Username,
		&user.Email,
		&user.Pass,
		&user.Role,
		&user.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}
