package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ctxKey string

const (
	SessionCookieName = "session"

	usernameKey ctxKey = "username"
	userIDKey   ctxKey = "user_id"
	roleKey     ctxKey = "role"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type createUserRequest struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Role     string    `json:"role"`
}

// ------------------HANDLERS------------------
// Login Handler
func (server *Server) Login(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}

	user, err := server.store.LookupByUsername(request.Context(), req.Username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(writer, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(writer, "server error", http.StatusInternalServerError)
		return
	}

	if !user.IsActive {
		http.Error(writer, "account is inactive", http.StatusForbidden)
		return
	}

	ok, err := VerifyPass(user.Pass, req.Password)
	if err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
	}
	if !ok {
		http.Error(writer, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, tokenHashRaw, err := NewSessionToken()
	if err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
		return
	}

	ttl := server.SessionTTL
	if ttl == 0 {
		ttl = 12 * time.Hour
	}

	expiresAt := time.Now().Add(ttl)
	tokenHash := tokenHashRaw[:]

	if err := server.store.SetUserSession(request.Context(), user.UserID, tokenHash, expiresAt); err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   server.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	writer.WriteHeader(http.StatusNoContent)
}

// Logout Handler
func (server *Server) Logout(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := UserIDFromContext(request.Context())
	if !ok {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := server.store.SetUserSession(request.Context(), userID, nil, time.Now()); err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   server.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) CreateUser(writer http.ResponseWriter, request http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role, ok := RoleFromContext(request.Context())
	if !ok || role != "admin" {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}

	var req createUserRequest
	if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Email == "" || req.Password == "" || req.Role == "" {
		http.Error(writer, "username, email, password, and role are required", http.StatusBadRequest)
		return
	}

	passHash, err := HashPass(req.Password, DefaultArgon2idParameters)
	if err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
		return
	}

	newUUID, err := uuid.NewV7()
	if err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
	}

	if err := server.store.CreateUser(request.Context(), newUUID, req.Username, req.Email, req.Password, req.Role); err != nil {

	}
}

// ------------------MIDDLEWARE------------------

// ------------------HELPERS------------------

// Token hashing helper
func hashSessionToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Helper to get UserID from context
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

// Helper to get Role from context
func RoleFromContext(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(roleKey).(string)
	return role, ok
}
