package store

import (
	"context"

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
