package recent

import (
	"GeoNET/control-plane/internal/geoip"
	"fmt"
	"sync"
)

type RingBuffer struct {
	mutex    sync.RWMutex
	data     []geoip.EnrichedRecord
	head     int // read element
	tail     int // write element
	size     int
	capacity int
}

func New(size int) (*RingBuffer, error) {
	if size < 1 {
		return &RingBuffer{}, fmt.Errorf("size must be greater than 0")
	}
	return &RingBuffer{
		data:     make([]geoip.EnrichedRecord, size),
		capacity: size,
	}, nil
}

func (rb *RingBuffer) Push(batch []geoip.EnrichedRecord) {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	for _, record := range batch {
		rb.data[rb.tail%rb.capacity] = record

		if rb.size == rb.capacity {
			rb.head = (rb.head + 1) % rb.capacity
		} else {
			rb.size = rb.size + 1
		}

		rb.tail = rb.tail + 1
	}
}

func (rb *RingBuffer) Snapshot() []geoip.EnrichedRecord {
	rb.mutex.RLock()
	defer rb.mutex.RUnlock()

	snapshot := make([]geoip.EnrichedRecord, rb.size)
	for i := range rb.size {
		snapshot[i] = rb.data[(rb.head+i)%rb.capacity]
	}

	return snapshot
}
