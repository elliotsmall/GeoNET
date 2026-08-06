package store

import (
	"context"
	"fmt"

	"GeoNET/control-plane/internal/geoip"

	"github.com/jackc/pgx/v5"
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
	batch := &pgx.Batch{}

	for _, r := range records {
		batch.Queue(
			`INSERT INTO flows (host_id, local_port, remote_addr, remote_port, protocol,
			 l7_protocol, bytes, packets, direction, timestamp, latitude, longitude, city, country)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			r.AgentID, r.FlowRecord.LocalPort, r.FlowRecord.RemoteAddr, r.FlowRecord.RemotePort,
			r.FlowRecord.IPProtocol, r.FlowRecord.L7Protocol, r.FlowRecord.Bytes, r.FlowRecord.Packets,
			r.FlowRecord.Direction, r.FlowRecord.Timestamp, r.Latitude, r.Latitude, r.Longitude, r.City, r.Country,
		)
	}

	results := store.pool.SendBatch(ctx, batch)
	defer results.Close()

	for range records {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("inserting flow record: %w", err)
		}
	}

	return nil
}
