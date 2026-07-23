package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"

	"GeoNET/control-plane/internal/store"
	"GeoNET/pkg/wire"

	"github.com/google/uuid"
)

// Takes POST requests from Agents sent to /ingest, gets token and agentID from batch
// calls verify credential then hands off batch
func handleIngest(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, err := extractBearerToken(request)
	if err != nil {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}

	batch, err := decodeFlowBatch(request)
	if err != nil {
		http.Error(writer, "malformed batch", http.StatusBadRequest)
		return
	}

	ok, err := verifyCredential(request.Context(), batch.AgentID, token)
	if err != nil {
		http.Error(writer, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}

}

// Takes in hostID and token from request, hashes to SHA256, calls look up of agentID and checks if credential hashes match
func verifyCredential(ctx context.Context, agentID uuid.UUID, token string) (bool, error) {
	data := []byte(token)
	tokenHashIncoming := sha256.Sum256(data)

	tokenHashStored, err := store.LookupAgent(ctx, agentID)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare(tokenHashIncoming[:], tokenHashStored[:]) == 1 {
		return true, nil
	} else {
		return false, fmt.Errorf("tokens do not match")
	}

}

// Function that takes request body and decodes from JSON to a FlowBatch object
func decodeFlowBatch(request *http.Request) (wire.FlowBatch, error) {
	decoder := json.NewDecoder(request.Body)
	var batch wire.FlowBatch

	if err := decoder.Decode(&batch); err != nil {
		return batch, fmt.Errorf("error decoding json: %v", err)
	}
	return batch, nil
}
