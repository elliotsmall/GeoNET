package ingest

import (
	"GeoNET/control-plane/internal/geoip"
	"GeoNET/control-plane/internal/store"
	"fmt"
	"net/http"
	"strings"
)

type Server struct {
	store *store.Store
	geoip *geoip.Enricher
}

func extractBearerToken(request *http.Request) (string, error) {
	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("auth header is missing")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	if token == authHeader || token == "" {
		return "", fmt.Errorf("invalid or malformed auth header")
	}

	return token, nil
}
