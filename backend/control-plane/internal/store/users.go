package store

import (
	"context"

	"fmt"
	"log"

	"github.com/google/uuid"
)

type User struct {
	UserID   uuid.UUID
	Username string
	Email    string
	PassHash string
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
		&user.UserID,
		&user.Email,
		&user.PassHash,
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
