package api

import (
	"GeoNET/control-plane/internal/recent"
	"GeoNET/control-plane/internal/store"
	"time"
)

type Server struct {
	store *store.Store

	CookieSecure bool

	SessionTTL time.Duration

	recent *recent.RingBuffer
}
