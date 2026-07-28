package store

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

func (store *Store) LookupAgent(ctx context.Context, agentID uuid.UUID) (string, error) {
	var token string
	err := store.pool.QueryRow(ctx, "SELECT token FROM agents WHERE agent_id = $1", agentID).Scan(&token)
	if err != nil {
		return token, fmt.Errorf("agent lookup: %w", err)
	}
	return token, nil
}

func (store *Store) InsertAgent(ctx context.Context, agentID uuid.UUID, tokenHash string, issuedAt time.Time) error {
	_, err := store.pool.Exec(ctx, "INSERT INTO agents (agent_id, token, issued_at) VALUES ($1, $2, $3)", agentID, tokenHash, issuedAt)
	if err != nil {
		return fmt.Errorf("inserting agent: %w", err)
	}
	log.Print("agent successfully inserted")
	return nil
}
