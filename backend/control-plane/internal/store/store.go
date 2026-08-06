package store

import (
	"context"
	"fmt"
	"time"

	"GeoNET/control-plane/internal/geoip"
	"GeoNET/pkg/api"

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

func (store *Store) QueryFlowsSince(ctx context.Context, start time.Time, agentID uuid.UUID) ([]api.GeoPoint, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT latitude, longitude, city, country, packets, bytes, remote_addr, direction
		FROM flows
		WHERE timestamp > $1 AND agent_id = $2
		ORDER BY timestamp`,
		start, agentID)
	if err != nil {
		return nil, fmt.Errorf("issue querying: %w", err)
	}
	defer rows.Close()

	var points []api.GeoPoint
	for rows.Next() {
		var p api.GeoPoint
		if err := rows.Scan(
			&p.Lat, &p.Lng, &p.City, &p.Country, &p.Packets, &p.Bytes, &p.RemoteAddr, &p.Direction,
		); err != nil {
			return nil, fmt.Errorf("scanning flow record: %w", err)
		}
		points = append(points, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading query results: %w", err)
	}

	return points, nil
}

func (store *Store) QueryTopNFlows(ctx context.Context, start time.Time, agentID uuid.UUID, n int) ([]api.GeoPoint, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT latitude, longitude, city, country, packets, bytes, remote_addr, direction
		FROM flows
		WHERE timestamp > $1 AND agent_id = $2
		ORDER BY packets DESC
		LIMIT $3`,
		start, agentID, n)
	if err != nil {
		return nil, fmt.Errorf("querying database: %w", err)
	}
	defer rows.Close()

	var points []api.GeoPoint
	for rows.Next() {
		var p api.GeoPoint
		if err := rows.Scan(
			&p.Lat, &p.Lng, &p.City, &p.Country, &p.Packets, &p.Bytes, &p.RemoteAddr, &p.Direction,
		); err != nil {
			return nil, fmt.Errorf("scanning flow record: %w", err)
		}
		points = append(points, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading query results: %w", err)
	}

	return points, nil
}

func (store *Store) AggregateSummary(ctx context.Context, start time.Time, agentID uuid.UUID) (uint64, uint64, int, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT COUNT(*) as total_flows, 
		SUM(packets) as total_packets,
		SUM(bytes) as total_bytes,
		COUNT(DISTINCT remote_addr) as unique_ips
		FROM flows
		WHERE timestamp > $1 AND agent_id = $2`,
		start, agentID)
}
