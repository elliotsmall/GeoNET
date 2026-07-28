package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const SessionTokenBytes = 32

func NewSessionToken() (token string, tokenHash [32]byte, err error) {
	raw := make([]byte, SessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, err
	}

	token = base64.RawURLEncoding.EncodeToString(raw)
	tokenHash = sha256.Sum256([]byte(token))
	return token, tokenHash, nil
}
