package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultArgon2idParameters = Argon2idParams{
	Memory:      64 * 1024,
	Iterations:  2,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPass(password string, params Argon2idParams) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password is empty")
	}

	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d,$%s,$%s",
		params.Memory, params.Iterations, params.Parallelism, saltB64, hashB64)

	return encoded, nil
}

func VerifyPass(encodedHash, password string) (bool, error) {
	if encodedHash == "" {
		return false, fmt.Errorf("hash is empty")
	}

	params, salt, hash, err := parseArgon2id(encodedHash)
	if err != nil {
		return false, err
	}

	newHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory,
		params.Parallelism, params.KeyLength)

	if subtle.ConstantTimeCompare(hash, newHash) == 1 {
		return true, nil
	}

	return false, nil
}

func parseArgon2id(encoded string) (Argon2idParams, []byte, []byte, error) {
	// parts 1-5:
	// 1 = argon2id
	// 2 = v19
	// 3 = m=_,t=_,p=_
	// 4 = salt base64
	// 5 = hash base64
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2idParams{}, nil, nil, fmt.Errorf("invalid argon2id hash format")
	}

	if parts[2] != "v=19" {
		return Argon2idParams{}, nil, nil, fmt.Errorf("incompatible argon2 version")
	}

	var params Argon2idParams
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("invalid params")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("invalid salt")
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("invalid hash")
	}

	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
