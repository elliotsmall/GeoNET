package ebpf

// Protocol constants - must match values in tc_monitor.c
// To add new protocols, define here and update in tc_monitor.c
const (
	ProtocolUnkown = 0
	ProtocolHTTP   = 1
	ProtocolHTTPS  = 2
	ProtocolDNS    = 3
	ProtocolSSH    = 4
)

// Connection States - must match values in tc_monitor.c
const (
	NewState         = 0
	EstablishedState = 1
	ClosingState     = 2
)

// FlowKey is a unique identifier for a flow
type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	_        [3]byte // Padding
}

// FlowStats tracks the statistics of a flow
type FlowStats struct {
	Packets      uint64
	Bytes        uint64
	LastSeen     uint64 //stores in nanoseconds
	FirstSeen    uint64 //stores in nanoseconds
	LatencySum   uint32 //stores in microseconds
	LatencyCount uint32
	State        uint8
	L7Protocol   uint8
	_            [2]byte // Padding
}

// ConnEvent gets sent when connection is established
type ConnEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	L7Protocol uint8
	State      uint8
	_          byte   // padding
	Timestamp  uint64 // in nanoseconds
}

func ProtocolToString(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return "Unknown"
	}
}

func L7ProtocolToString(protocol uint8) string {
	switch protocol {
	case ProtocolHTTP:
		return "HTTP"
	case ProtocolHTTPS:
		return "HTTPS"
	case ProtocolDNS:
		return "DNS"
	case ProtocolSSH:
		return "SSH"
	default:
		return ""
	}
}

func StateToString(state uint8) string {
	switch state {
	case NewState:
		return "New"
	case EstablishedState:
		return "Established"
	case ClosingState:
		return "Closing"
	default:
		return "Unknown"
	}
}
