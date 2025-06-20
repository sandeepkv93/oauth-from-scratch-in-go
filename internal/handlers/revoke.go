package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	r.ParseForm()
	
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if token == "" {
		h.sendError(w, "invalid_request", "Token parameter required", http.StatusBadRequest)
		return
	}

	if clientID == "" {
		clientID, clientSecret = extractBasicAuth(r)
	}

	if clientID == "" {
		h.sendError(w, "invalid_client", "Client authentication required", http.StatusUnauthorized)
		return
	}

	client, err := h.auth.ValidateClient(clientID, clientSecret)
	if err != nil {
		h.sendError(w, "invalid_client", "Client authentication failed", http.StatusUnauthorized)
		return
	}

	var revoked bool

	switch tokenTypeHint {
	case "refresh_token":
		revoked = h.tryRevokeRefreshToken(token, client.ClientID)
		if !revoked {
			revoked = h.tryRevokeAccessToken(token, client.ClientID)
		}
	case "access_token":
		revoked = h.tryRevokeAccessToken(token, client.ClientID)
		if !revoked {
			revoked = h.tryRevokeRefreshToken(token, client.ClientID)
		}
	default:
		revoked = h.tryRevokeAccessToken(token, client.ClientID)
		if !revoked {
			revoked = h.tryRevokeRefreshToken(token, client.ClientID)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

func (h *Handler) tryRevokeAccessToken(token, clientID string) bool {
	accessToken, err := h.db.GetAccessToken(token)
	if err != nil {
		return false
	}
	
	if accessToken.ClientID != clientID {
		return false
	}

	err = h.db.RevokeAccessToken(accessToken.ID)
	return err == nil
}

func (h *Handler) tryRevokeRefreshToken(token, clientID string) bool {
	refreshToken, err := h.db.GetRefreshToken(token)
	if err != nil {
		return false
	}
	
	if refreshToken.ClientID != clientID {
		return false
	}

	err = h.db.RevokeRefreshToken(token)
	return err == nil
}

func extractBasicAuth(r *http.Request) (username, password string) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", ""
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return "", ""
	}

	encoded := auth[len(prefix):]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", ""
	}

	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return parts[0], parts[1]
}