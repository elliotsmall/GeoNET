package api

import (
	"time"
)

type GeoPoint struct {
	Lat       float64 `json:"lat"`
	Lng       float64 `json:"lng"`
	City      string  `json:"city"`
	Country   string  `json:"country"`
	ASN       string  `json:"asn"`
	Packets   uint64  `json:"packets"`
	Bytes     uint64  `json:"bytes"`
	FlowCount uint64  `json:"flow_count"`
}

type NetworkSummary struct {
	TotalFlows   int    `json:"total_flows"`
	TotalPackets uint64 `json:"total_packets"`
	TotalBytes   uint64 `json:"total_bytes"`
	UniqueIPs    int    `json:"unique_ips"`
}

type TopologyNode struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	IsLocal bool   `json:"is_local"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type TopologyEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

type TopologyGraph struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}

type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type GeoView struct {
	Window  Window         `json:"window"`
	Points  []GeoPoint     `json:"points"`
	TopN    []GeoPoint     `json:"top_n"`
	Summary NetworkSummary `json:"summary"`
}

type TopologyView struct {
	Window  Window         `json:"window"`
	Graph   TopologyGraph  `json:"graph"`
	Summary NetworkSummary `json:"summary"`
}
