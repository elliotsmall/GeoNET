package ingest

import (
	"fmt"
	"net/http"
	"strings"
)

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
