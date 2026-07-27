package ingest

import (
	"GeoNET/pkg/wire"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

// Precondition - main.go verifies that BOOTSTRAP_KEY env var exists and is populated
func handleEnroll(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, err := extractBearerToken(request)
	if err != nil {
		http.Error(writer, "auth header issue", http.StatusBadRequest)
	}

	knownToken := os.Getenv("BOOTSTRAP_KEY")
	ok := knownToken == token
	if !ok {
		http.Error(writer, "invalid token", http.StatusUnauthorized)
	}

}

func generateCredential() (wire.Credential, string, error) {
	agentID := uuid.New()

	token, err := generateToken()
	if err != nil {
		return wire.Credential{}, "", err
	}

	tokenHash := hashToken(token)

	return wire.Credential{
		AgentID:  agentID,
		Token:    token,
		IssuedAt: time.Now(),
	}, tokenHash, nil
}

func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
