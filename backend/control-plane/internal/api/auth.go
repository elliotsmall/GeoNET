package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

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

	if err := server.store.SetUserSession(request.Context(), user.UserID, user.Username, tokenHash, expiresAt); err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   server.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) Logout(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, username, ok := UserIDContext(request.Context())
	if !ok {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := server.store.SetUserSession(request.Context(), userID, username, nil, time.Now()); err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   server.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	writer.WriteHeader(http.StatusNoContent)
}
