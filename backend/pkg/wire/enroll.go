package wire

import (
	"time"
)

// Enroll request: agent presents enrollment and recevies credential
type EnrollRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	AgentVersion string `json:"agent_version"`
}

type EnrollResponse struct {
	HostID   string    `json:"host_id"`
	AgentKey string    `json:"agent_key"` // Credential that holds for subsequent pushes
	IssuedAt time.Time `json:"issued_at"`
}

// IngestResponse, control plane ack of a FlowBatch
type IngestResponse struct {
	Accepted int    `json:"accepted"`
	Rejected int    `json:"rejected"`
	Error    string `json:"error,omitempty"`
}
