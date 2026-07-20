//go:build linux

package capture

import (
	"GeoNET/traffic-collector/internal/ebpf"
	"fmt"
	"net/netip"
)

// Capture source constructor
func New(iface string, localIPs map[netip.Addr]struct{}) (Source, error) {
	return newEBPFSource(iface, localIPs)
}

// ebpfSource adapts kernel eBPF flow map to capture.Source

type ebpfSource struct {
	monitor  *ebpf.Monitor
	localIPs map[netip.Addr]struct{}
	previous map[ebpf.FlowKey]counters
}

type counters struct {
	packets, bytes uint64
}

func newEBPFSource(iface string, localIPs map[netip.Addr]struct{}) (*ebpfSource, error) {
	monitor, err := ebpf.NewMonitor(iface)
	if err != nil {
		return nil, err
	}
	return &ebpfSource{
		monitor:  monitor,
		localIPs: localIPs,
		previous: make(map[ebpf.FlowKey]counters),
	}, nil
}

func (source *ebpfSource) Drain() ([]Flow, error) {
	snapshot, err := source.monitor.GetAllFlows() //map[ebpf.FlowKey]ebpf.FlowStats
	if err != nil {
		return nil, fmt.Errorf("reading flow map: %w", err)
	}

	out := make([]Flow, 0, len(snapshot))
	seen := make(map[ebpf.FlowKey]counters, len(snapshot))

	for key, stats := range snapshot {
		current := counters{packets: stats.Packets, bytes: stats.Bytes}
		seen[key] = current //baseline for next drain even if delta is 0

		prev := source.previous[key]
		delta := counters{current.packets - prev.packets, current.bytes - prev.bytes}
		// New flow (prev = 0) or counter reset
		if current.packets < prev.packets || current.bytes < prev.bytes {
			delta = current
		}
		if delta.packets == 0 && delta.bytes == 0 {
			continue // no traffic on flow during this window
		}

		if flow, ok := source.toFlow(key, stats, delta); ok {
			out = append(out, flow)
		}
	}

	// Flows absent from snapshot get replaced by seen flows
	source.previous = seen
	return out, nil
}

func (source *ebpfSource) toFlow(key ebpf.FlowKey, stats ebpf.FlowStats, delta counters) (Flow, bool) {
	src := addrFromu32(key.SrcIP)
	dst := addrFromu32(key.DstIP)

	flow := Flow{
		Proto:   key.Protocol,
		L7Proto: stats.L7Protocol,
		Packets: delta.packets,
		Bytes:   delta.bytes,
	}

	_, srcLocal := source.localIPs[src]
	_, dstLocal := source.localIPs[dst]

	switch {
	case srcLocal && !dstLocal: // local -> remote outbound traffic
		flow.Remote, flow.RemotePort, flow.LocalPort, flow.Direction = dst, key.DstPort, key.SrcPort, DirOutbound
	case dstLocal && !srcLocal: // remote -> local inbound traffic
		flow.Remote, flow.RemotePort, flow.LocalPort, flow.Direction = src, key.SrcPort, key.DstPort, DirInbound
	default: //both local or neither local. Nothing to geolocate, so skip.
		return Flow{}, false
	}

	return flow, true
}

func (source *ebpfSource) Close() error { return source.monitor.Close() }

func addrFromu32(ip uint32) netip.Addr {
	address, _ := netip.AddrFromSlice(ebpf.Uint32ToIP(ip))
	return address.Unmap()
}
