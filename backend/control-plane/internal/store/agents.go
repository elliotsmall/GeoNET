package store

import (
	"context"

	"github.com/google/uuid"
)

func LookupAgent(ctx context.Context, hostID uuid.UUID) ([32]byte, error) {
	const query = `
	SELECT token
	FROM agents
	WHERE hostID = ?
	LIMIT 1;`

	return tokenHash, err
}
