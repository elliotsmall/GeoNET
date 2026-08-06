package api

import (
	"GeoNET/control-plane/internal/geoip"
	"GeoNET/pkg/api"
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

func (s *Server) RealTimeFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestedN := 10

	if v := r.URL.Query().Get("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			requestedN = n
		}
	}

	records := s.recent.Snapshot()
	if len(records) == 0 {
		view := &api.GeoView{
			Window:  api.Window{},
			Points:  []api.GeoPoint{},
			TopN:    []api.GeoPoint{},
			Summary: api.NetworkSummary{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(view)
		return
	}

	points := make([]api.GeoPoint, len(records))
	for i, record := range records {
		points[i] = api.GeoPoint{
			Lat:     record.Latitude,
			Lng:     record.Longitude,
			City:    record.City,
			Country: record.Country,
			Packets: record.FlowRecord.Packets,
			Bytes:   record.FlowRecord.Bytes,
		}
	}

	window := api.Window{
		Start: records[0].FlowRecord.Timestamp,
		End:   records[len(records)-1].FlowRecord.Timestamp,
	}

	totalPackets, totalBytes, uniqueIPs := calculateTotals(records)

	summary := api.NetworkSummary{
		TotalFlows:   len(records),
		TotalPackets: totalPackets,
		TotalBytes:   totalBytes,
		UniqueIPs:    uniqueIPs,
	}

	topN := realTimeTopN(records, requestedN)

	view := &api.GeoView{
		Window:  window,
		Points:  points,
		TopN:    topN,
		Summary: summary,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (s *Server) FlowsByWindow(w http.ResponseWriter, r *http.Request) {
	window, err := parseWindow(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}

func (s *Server) TopologyByWindow(w http.ResponseWriter, r *http.Request) {

}

func (s *Server) TopNByWindow(w http.ResponseWriter, r *http.Request) {

}

func (s *Server) SummaryByWindow(w http.ResponseWriter, r *http.Request) {

}

// ========== HELPER FUNCTIONS ==========

// Helper function to sort the ringbuffer snapshot
func realTimeTopN(records []geoip.EnrichedRecord, requestedN int) []api.GeoPoint {
	sorted := slices.Clone(records)
	slices.SortFunc(sorted, func(a, b geoip.EnrichedRecord) int {
		return cmp.Compare(b.FlowRecord.Packets, a.FlowRecord.Packets)
	})

	n := min(len(sorted), requestedN)

	topN := make([]api.GeoPoint, n)

	// loops over the count N and appends the first N records
	for i := range n {
		topN[i] = api.GeoPoint{
			Lat:     sorted[i].Latitude,
			Lng:     sorted[i].Longitude,
			City:    sorted[i].City,
			Country: sorted[i].Country,
			Packets: sorted[i].FlowRecord.Packets,
			Bytes:   sorted[i].FlowRecord.Bytes,
		}
	}

	return topN
}

func calculateTotals(records []geoip.EnrichedRecord) (uint64, uint64, int) {
	var totalPackets uint64
	var totalBytes uint64
	uniqueIPs := map[netip.Addr]struct{}{}
	for _, record := range records {
		totalPackets += record.FlowRecord.Packets

		totalBytes += record.FlowRecord.Bytes

		uniqueIPs[record.FlowRecord.RemoteAddr] = struct{}{}
	}

	return totalPackets, totalBytes, len(uniqueIPs)
}

// Helper to read window from url and calculate timestamps for window
func parseWindow(r *http.Request) (api.Window, error) {
	v := r.URL.Query().Get("window")

	var d time.Duration
	switch v {
	case "1h":
		d = time.Hour
	case "3h":
		d = 3 * time.Hour
	case "6h":
		d = 6 * time.Hour
	case "12h":
		d = 12 * time.Hour
	case "24h":
		d = 24 * time.Hour
	default:
		return api.Window{}, fmt.Errorf("invalid window: %q", v)
	}

	end := time.Now()
	start := end.Add(-d)

	return api.Window{Start: start, End: end}, nil
}
