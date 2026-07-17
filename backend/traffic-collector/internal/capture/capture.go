package capture

import "net/netip"

// Tells consumer which endpoint is remote
// Resolves by comparing flow endpoints against host addresses
type Direction uint8

const (
	DirOutbound Direction = iota //local host init, remote is destination
	DirInbound                   //remote initiated, local is destination
)

func (d Direction) String() string {
	switch d {
	case DirInbound:
		return "inbound"
	case DirOutbound:
		return "outbound"
	default:
		return "unknown"
	}
}

type Flow struct {
	Remote     netip.Addr
	RemotePort uint16
	LocalPort  uint16
	Proto      uint8
	L7Proto    uint8
	Direction  Direction
	Packets    uint64
	Bytes      uint64
}

type Source interface {
	Drain() ([]Flow, error)
	Close() error
}
