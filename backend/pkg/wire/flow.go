package wire

import (
	"net/netip"
	"time"
)

// Tells the direction of the flow for geolocation purposes
type Direction uint8

const (
	DirectionEgress  Direction = 0 // geolocate egress traffic (agent -> remote)
	DirectionIngress Direction = 1 // geolocate ingress traffic (remote -> agent)
)

type FlowRecord struct {
	RemoteAddr netip.Addr `json:"remote_addr"`
	RemotePort uint16     `json:"remote_port"`
	LocalPort  uint16     `json:"local_port"`

	IPProtocol uint8     `json:"ip_protocol"` // 6 TCP, 17 UDP, 1 ICMP
	L7Protocol uint8     `json:"l7_protocol"`
	Direction  Direction `json:"direction"`

	Packets uint64 `json:"packets"`
	TxBytes uint64 `json:"tx_bytes"`
	RxBytes uint64 `json:"rx_bytes"`
}

type FlowBatch struct {
	HostID      string       `json:"host_id"`
	BucketStart time.Time    `json:"bucket_start"`
	BucketEnd   time.Time    `json:"bucket_end"`
	Records     []FlowRecord `json:"records"`
}
