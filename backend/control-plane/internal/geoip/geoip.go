package geoip

import (
	"GeoNET/pkg/wire"
	"context"
	"net"
	"net/netip"

	"fmt"
	"log"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/oschwald/geoip2-golang"
)

type Enricher struct {
	db    *geoip2.Reader
	cache *lru.Cache[netip.Addr, *geoip2.City]
}

type EnrichedRecord struct {
	flowRecord wire.FlowRecord
	Latitude   float64
	Longitude  float64
	Country    string
	City       string
}

func New(mmdbPath string) (*Enricher, error) {
	db, err := geoip2.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("opening GeoLite2 db: %v", err)
	}

	cache, err := lru.New[netip.Addr, *geoip2.City](4096)
	if err != nil {
		return nil, fmt.Errorf("creating LRU cache: %v", err)
	}
	return &Enricher{db, cache}, nil
}

func (enricher *Enricher) Enrich(ctx context.Context, batch wire.FlowBatch) ([]EnrichedRecord, error) {
	geoRecords := make([]EnrichedRecord, 0, len(batch.Records))
	for _, record := range batch.Records {

		geoStats, ok := enricher.cache.Get(record.RemoteAddr)
		// ok signals cache hit (True) or miss (False)
		if !ok {
			var err error
			geoStats, err = enricher.db.City(net.IP(record.RemoteAddr.AsSlice()))
			if err != nil {
				log.Printf("query geolite db: %v", err)
				geoStats = nil
			}
			enricher.cache.Add(record.RemoteAddr, geoStats)
		}

		lat, long, country, city := geoFields(geoStats)
		geoRecords = append(geoRecords, EnrichedRecord{
			flowRecord: record,
			Latitude:   lat,
			Longitude:  long,
			Country:    country,
			City:       city,
		})
	}

	return geoRecords, nil
}

func geoFields(geoStats *geoip2.City) (float64, float64, string, string) {
	if geoStats == nil {
		return 0, 0, "", ""
	}
	return geoStats.Location.Latitude, geoStats.Location.Longitude, geoStats.Country.Names["en"], geoStats.City.Names["en"]
}
