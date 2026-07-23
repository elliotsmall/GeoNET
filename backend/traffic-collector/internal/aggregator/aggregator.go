package aggregator

import (
	"context"
	"log"
	"time"

	"GeoNET/pkg/wire"
	"GeoNET/traffic-collector/internal/capture"

	"github.com/google/uuid"
)

// Assembled batches sent to Sink.
type Sink interface {
	Send(batch wire.FlowBatch) error
}

type Aggregator struct {
	source   capture.Source
	sink     Sink
	agentID  uuid.UUID
	interval time.Duration

	bucketStart time.Time
}

func New(source capture.Source, sink Sink, agentID uuid.UUID, interval time.Duration) *Aggregator {
	return &Aggregator{
		source:   source,
		sink:     sink,
		agentID:  agentID,
		interval: interval,
	}
}

func (agg *Aggregator) Run(ctx context.Context) error {
	agg.bucketStart = time.Now()

	ticker := time.NewTicker(agg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			agg.flush(time.Now())
			return ctx.Err()

		case now := <-ticker.C:
			agg.flush(now)
		}
	}
}

func (agg *Aggregator) flush(end time.Time) {
	flows, err := agg.source.Drain()
	if err != nil {
		log.Printf("aggregator: drain %v", err)
		return
	}

	records := make([]wire.FlowRecord, 0, len(flows))
	for _, flow := range flows {
		if !flow.Remote.IsValid() ||
			flow.Remote.IsPrivate() ||
			flow.Remote.IsLoopback() ||
			flow.Remote.IsLinkLocalUnicast() ||
			flow.Remote.IsMulticast() ||
			flow.Remote.IsUnspecified() {
			continue
		}
		records = append(records, toRecord(flow))
	}

	batch := wire.FlowBatch{
		AgentID:     agg.agentID,
		BucketStart: agg.bucketStart,
		BucketEnd:   end,
		Records:     records,
	}

	if err := agg.sink.Send(batch); err != nil {
		log.Printf("aggregator: send: %v", err)
	}

	agg.bucketStart = end
}

func toRecord(flow capture.Flow) wire.FlowRecord {
	record := wire.FlowRecord{
		RemoteAddr: flow.Remote,
		RemotePort: flow.RemotePort,
		LocalPort:  flow.LocalPort,
		IPProtocol: flow.Proto,
		L7Protocol: flow.L7Proto,
		Direction:  wire.Direction(flow.Direction),
		Packets:    flow.Packets,
		Bytes:      flow.Bytes,
	}

	return record
}
