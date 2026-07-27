package store

import (
	"context"
	"fmt"

	"GeoNET/control-plane/internal/geoip"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, connString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (store *Store) InsertBatch(ctx context.Context, records []geoip.EnrichedRecord) error {

	return nil
}
