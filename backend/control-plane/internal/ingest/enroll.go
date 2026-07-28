package ingest

import (
	"GeoNET/pkg/wire"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

// Precondition - main.go verifies that BOOTSTRAP_KEY env var exists and is populated
func (server *Server) handleEnroll(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, err := extractBearerToken(request)
	if err != nil {
		http.Error(writer, "auth header issue", http.StatusBadRequest)
		return
	}

	knownToken := os.Getenv("BOOTSTRAP_KEY")
	ok := subtle.ConstantTimeCompare([]byte(knownToken), []byte(token)) == 1
	if !ok {
		http.Error(writer, "invalid token", http.StatusUnauthorized)
		return
	}

	credential, tokenHash, err := generateCredential()
	if err != nil {
		log.Printf("generating credential: %v", err)
		http.Error(writer, "internal error", http.StatusInternalServerError)
		return
	}

	if err := server.store.InsertAgent(request.Context(), credential.AgentID, tokenHash, credential.IssuedAt); err != nil {
		log.Printf("persisting credential: %v", err)
		http.Error(writer, "internal error", http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(writer).Encode(credential); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func generateCredential() (wire.Credential, string, error) {
	agentID, err := uuid.NewV7()
	if err != nil {
		return wire.Credential{}, "", fmt.Errorf("generating uuid: %w", err)
	}

	token, err := generateToken()
	if err != nil {
		return wire.Credential{}, "", fmt.Errorf("generating token: %w", err)
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
		return "", fmt.Errorf("generating token bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
