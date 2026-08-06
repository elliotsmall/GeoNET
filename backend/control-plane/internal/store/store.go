package store

import (
	"context"
	"fmt"
	"time"

	"GeoNET/control-plane/internal/geoip"

	"github.com/google/uuid"
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
			`INSERT INTO flows (agent_id, local_port, remote_addr, remote_port, protocol,
			 l7_protocol, bytes, packets, direction, timestamp, latitude, longitude, city, country)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			r.AgentID, r.FlowRecord.LocalPort, r.FlowRecord.RemoteAddr, r.FlowRecord.RemotePort,
			r.FlowRecord.IPProtocol, r.FlowRecord.L7Protocol, r.FlowRecord.Bytes, r.FlowRecord.Packets,
			r.FlowRecord.Direction, r.FlowRecord.Timestamp, r.Latitude, r.Longitude, r.City, r.Country,
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

func (store *Store) QueryFlowsSince(ctx context.Context, start time.Time, agentID uuid.UUID) ([]geoip.EnrichedRecord, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT agent_id, local_port, remote_addr, remote_port, protocol, l7_protocol, bytes,
		packets, direction, timestamp, latitude, longitude, city, country
		FROM flows
		WHERE timestamp > $1 AND ($2::uuid IS NULL OR agent_id = $2)
		ORDER BY timestamp`,
		start, agentID)
	if err != nil {
		return nil, fmt.Errorf("issue querying: %w", err)
	}
	defer rows.Close()

	var records []geoip.EnrichedRecord
	for rows.Next() {
		var r geoip.EnrichedRecord
		if err := rows.Scan(
			&r.AgentID,
			&r.FlowRecord.LocalPort,
			&r.FlowRecord.RemoteAddr,
			&r.FlowRecord.RemotePort,
			&r.FlowRecord.IPProtocol,
			&r.FlowRecord.L7Protocol,
			&r.FlowRecord.Bytes,
			&r.FlowRecord.Packets,
			&r.FlowRecord.Direction,
			&r.FlowRecord.Timestamp,
			&r.Latitude,
			&r.Longitude,
			&r.City,
			&r.Country,
		); err != nil {
			return nil, fmt.Errorf("scanning flow record: %w", err)
		}
		records = append(records, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading query results: %w", err)
	}

	return records, nil
}
