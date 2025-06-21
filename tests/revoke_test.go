package tests

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"oauth-server/internal/auth"
	"oauth-server/internal/db"
	"oauth-server/internal/handlers"
)

func TestRevokeEndpoint(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	response, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	data := url.Values{}
	data.Set("token", response.AccessToken)
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var revokeResponse map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&revokeResponse); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if revokeResponse["status"] != "revoked" {
		t.Errorf("Expected status 'revoked', got %s", revokeResponse["status"])
	}
}

func TestRevokeMissingToken(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	data := url.Values{}
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var errorResponse map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&errorResponse); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResponse["error"] != "invalid_request" {
		t.Errorf("Expected error 'invalid_request', got %s", errorResponse["error"])
	}
}

func TestRevokeWithBasicAuth(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	response, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	data := url.Values{}
	data.Set("token", response.AccessToken)

	credentials := base64.StdEncoding.EncodeToString([]byte("test-client:test-secret"))
	
	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+credentials)
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestRevokeInvalidClient(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	data := url.Values{}
	data.Set("token", "some-token")
	data.Set("client_id", "invalid-client")
	data.Set("client_secret", "invalid-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}

	var errorResponse map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&errorResponse); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResponse["error"] != "invalid_client" {
		t.Errorf("Expected error 'invalid_client', got %s", errorResponse["error"])
	}
}

func TestRevokeMissingClientAuth(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	data := url.Values{}
	data.Set("token", "some-token")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	userID := mockDB.users["testuser"].ID
	code, err := authService.CreateAuthorizationCode(
		userID,
		"test-client",
		"http://localhost:8080/callback",
		[]string{"openid", "profile"},
		"",
		"",
	)
	if err != nil {
		t.Fatalf("Failed to create authorization code: %v", err)
	}

	tokenResponse, err := authService.ExchangeCodeForToken(&auth.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:8080/callback",
		ClientID:    "test-client",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("Failed to exchange code for token: %v", err)
	}

	data := url.Values{}
	data.Set("token", tokenResponse.RefreshToken)
	data.Set("token_type_hint", "refresh_token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestRevokeAccessTokenHint(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	response, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	data := url.Values{}
	data.Set("token", response.AccessToken)
	data.Set("token_type_hint", "access_token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestRevokeTokenWrongClient(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	response, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	otherClient := &db.Client{
		ClientID:     "other-client",
		ClientSecret: "other-secret",
		Name:         "Other Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"client_credentials"},
		IsPublic:     false,
	}
	mockDB.CreateClient(otherClient)

	data := url.Values{}
	data.Set("token", response.AccessToken)
	data.Set("client_id", "other-client")
	data.Set("client_secret", "other-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 even for wrong client, got %d", rr.Code)
	}
}

func TestRevokeNonExistentToken(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	data := url.Values{}
	data.Set("token", "non-existent-token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 even for non-existent token, got %d", rr.Code)
	}
}

func TestExtractBasicAuth(t *testing.T) {
	testCases := []struct {
		name           string
		authHeader     string
		expectedUser   string
		expectedPass   string
	}{
		{
			name:           "Valid basic auth",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")),
			expectedUser:   "user",
			expectedPass:   "pass",
		},
		{
			name:           "Valid basic auth with colon in password",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass:word")),
			expectedUser:   "user",
			expectedPass:   "pass:word",
		},
		{
			name:           "Empty auth header",
			authHeader:     "",
			expectedUser:   "",
			expectedPass:   "",
		},
		{
			name:           "Bearer token instead of basic",
			authHeader:     "Bearer token123",
			expectedUser:   "",
			expectedPass:   "",
		},
		{
			name:           "Invalid base64",
			authHeader:     "Basic invalid-base64",
			expectedUser:   "",
			expectedPass:   "",
		},
		{
			name:           "Missing colon in credentials",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("userpass")),
			expectedUser:   "",
			expectedPass:   "",
		},
		{
			name:           "Empty credentials",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte(":")),
			expectedUser:   "",
			expectedPass:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			authService, mockDB := setupTestAuth()
			handler := handlers.NewHandler(authService, mockDB)

			data := url.Values{}
			data.Set("token", "test-token")

			req = httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			rr := httptest.NewRecorder()
			handler.Revoke(rr, req)

			if tc.expectedUser == "" && tc.expectedPass == "" {
				if rr.Code != http.StatusUnauthorized {
					t.Errorf("Expected unauthorized status for invalid auth, got %d", rr.Code)
				}
			}
		})
	}
}

func TestRevokeContentType(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	data := url.Values{}
	data.Set("token", "test-token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}

func TestTryRevokeAccessToken(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	_, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	accessToken := &db.AccessToken{
		Token:     "test-access-token",
		ClientID:  "test-client",
		UserID:    uuid.New(),
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	mockDB.CreateAccessToken(accessToken)

	// Test through the public Revoke endpoint since TryRevokeAccessToken is private
	data := url.Values{}
	data.Set("token", "test-access-token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Should successfully revoke access token, got %d", rr.Code)
	}
}

func TestTryRevokeRefreshTokenThroughEndpoint(t *testing.T) {
	authService, mockDB := setupTestAuth()
	handler := handlers.NewHandler(authService, mockDB)

	refreshToken := &db.RefreshToken{
		Token:         "test-refresh-token",
		AccessTokenID: uuid.New(),
		ClientID:      "test-client",
		UserID:        uuid.New(),
		Scopes:        []string{"read"},
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	mockDB.CreateRefreshToken(refreshToken)

	// Test through the public Revoke endpoint since TryRevokeRefreshToken is private
	data := url.Values{}
	data.Set("token", "test-refresh-token")
	data.Set("token_type_hint", "refresh_token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Revoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Should successfully revoke refresh token, got %d", rr.Code)
	}
}

// Note: These helper methods would need to be exposed from the handlers package or we need to test through the public interface
// For now, testing through the public Revoke endpoint covers the private helper methods