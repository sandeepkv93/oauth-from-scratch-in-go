package tests

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/auth"
	"oauth-server/internal/db"
)

func TestTokenExchange(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client for token exchange
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("exchange-client-secret"), bcrypt.DefaultCost)
	exchangeClient := &db.Client{
		ClientID:     "exchange-client",
		ClientSecret: string(hashedSecret),
		Name:         "Token Exchange Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write", "admin"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		IsPublic:     false,
	}
	mockDB.CreateClient(ctx, exchangeClient)

	// Test user is available for future tests that need it
	_ = mockDB.users

	// First, create an access token to use as subject token
	subjectTokenResponse, err := authService.ClientCredentialsGrant(ctx, &auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read write",
	})
	if err != nil {
		t.Fatalf("Failed to create subject token: %v", err)
	}

	// Test basic token exchange
	req := &auth.TokenRequest{
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:           "exchange-client",
		ClientSecret:       "exchange-client-secret",
		SubjectToken:       subjectTokenResponse.AccessToken,
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Scope:              "read",
	}

	response, err := authService.TokenExchange(ctx, req)
	if err != nil {
		t.Errorf("Expected successful token exchange, got error: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}
	if response.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}
	if response.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", response.TokenType)
	}
	if response.Scope != "read" {
		t.Errorf("Expected scope 'read', got '%s'", response.Scope)
	}

	// Verify the new token can be validated
	claims, err := authService.ValidateAccessToken(response.AccessToken)
	if err != nil {
		t.Errorf("Failed to validate exchanged token: %v", err)
	}
	if claims.ClientID != "exchange-client" {
		t.Errorf("Expected client ID 'exchange-client', got '%s'", claims.ClientID)
	}
}

func TestTokenExchangeWithRefreshToken(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client for token exchange
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("exchange-client-secret"), bcrypt.DefaultCost)
	exchangeClient := &db.Client{
		ClientID:     "exchange-refresh-client",
		ClientSecret: string(hashedSecret),
		Name:         "Token Exchange Refresh Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		IsPublic:     false,
	}
	mockDB.CreateClient(ctx, exchangeClient)

	// Create an access token to use as subject token
	subjectTokenResponse, err := authService.ClientCredentialsGrant(ctx, &auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read write",
	})
	if err != nil {
		t.Fatalf("Failed to create subject token: %v", err)
	}

	// Test token exchange using refresh token as subject
	req := &auth.TokenRequest{
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:           "exchange-refresh-client",
		ClientSecret:       "exchange-client-secret",
		SubjectToken:       subjectTokenResponse.RefreshToken,
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:refresh_token",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Scope:              "read",
	}

	response, err := authService.TokenExchange(ctx, req)
	if err != nil {
		t.Errorf("Expected successful token exchange with refresh token, got error: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}
	if response.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}
}

func TestTokenExchangeInvalidSubjectToken(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client for token exchange
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("exchange-client-secret"), bcrypt.DefaultCost)
	exchangeClient := &db.Client{
		ClientID:     "exchange-invalid-client",
		ClientSecret: string(hashedSecret),
		Name:         "Token Exchange Invalid Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		IsPublic:     false,
	}
	mockDB.CreateClient(ctx, exchangeClient)

	req := &auth.TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         "exchange-invalid-client",
		ClientSecret:     "exchange-client-secret",
		SubjectToken:     "invalid-token",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}

	_, err := authService.TokenExchange(ctx, req)
	if err == nil {
		t.Error("Expected error for invalid subject token")
	}
}

func TestTokenExchangeUnsupportedGrantType(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client that doesn't support token exchange
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("no-exchange-secret"), bcrypt.DefaultCost)
	noExchangeClient := &db.Client{
		ClientID:     "no-exchange-client",
		ClientSecret: string(hashedSecret),
		Name:         "No Exchange Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"client_credentials"}, // No token exchange grant
		IsPublic:     false,
	}
	mockDB.CreateClient(ctx, noExchangeClient)

	// Create subject token
	subjectTokenResponse, err := authService.ClientCredentialsGrant(ctx, &auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Failed to create subject token: %v", err)
	}

	req := &auth.TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         "no-exchange-client",
		ClientSecret:     "no-exchange-secret",
		SubjectToken:     subjectTokenResponse.AccessToken,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}

	_, err = authService.TokenExchange(ctx, req)
	if err == nil {
		t.Error("Expected error for unsupported grant type")
	}
	if err != auth.ErrInvalidGrant {
		t.Errorf("Expected ErrInvalidGrant, got: %v", err)
	}
}

func TestTokenExchangeMissingParameters(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client for token exchange
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("exchange-client-secret"), bcrypt.DefaultCost)
	exchangeClient := &db.Client{
		ClientID:     "exchange-missing-client",
		ClientSecret: string(hashedSecret),
		Name:         "Token Exchange Missing Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		IsPublic:     false,
	}
	mockDB.CreateClient(ctx, exchangeClient)

	// Test missing subject token
	req := &auth.TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         "exchange-missing-client",
		ClientSecret:     "exchange-client-secret",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}

	_, err := authService.TokenExchange(ctx, req)
	if err == nil {
		t.Error("Expected error for missing subject token")
	}

	// Test missing subject token type
	req = &auth.TokenRequest{
		GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:     "exchange-missing-client",
		ClientSecret: "exchange-client-secret",
		SubjectToken: "some-token",
	}

	_, err = authService.TokenExchange(ctx, req)
	if err == nil {
		t.Error("Expected error for missing subject token type")
	}
}

func TestTokenExchangeUnsupportedTokenType(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client for token exchange
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("exchange-client-secret"), bcrypt.DefaultCost)
	exchangeClient := &db.Client{
		ClientID:     "exchange-unsupported-client",
		ClientSecret: string(hashedSecret),
		Name:         "Token Exchange Unsupported Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		IsPublic:     false,
	}
	mockDB.CreateClient(ctx, exchangeClient)

	req := &auth.TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         "exchange-unsupported-client",
		ClientSecret:     "exchange-client-secret",
		SubjectToken:     "some-token",
		SubjectTokenType: "unsupported-token-type",
	}

	_, err := authService.TokenExchange(ctx, req)
	if err == nil {
		t.Error("Expected error for unsupported token type")
	}
}

func TestTokenExchangeScopeDowngrade(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client for token exchange with limited scopes
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("exchange-client-secret"), bcrypt.DefaultCost)
	exchangeClient := &db.Client{
		ClientID:     "exchange-scope-client",
		ClientSecret: string(hashedSecret),
		Name:         "Token Exchange Scope Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read"}, // Only read scope allowed
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		IsPublic:     false,
	}
	mockDB.CreateClient(ctx, exchangeClient)

	// Create subject token with broader scopes
	subjectTokenResponse, err := authService.ClientCredentialsGrant(ctx, &auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read write",
	})
	if err != nil {
		t.Fatalf("Failed to create subject token: %v", err)
	}

	// Exchange token - should automatically downgrade scopes
	req := &auth.TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         "exchange-scope-client",
		ClientSecret:     "exchange-client-secret",
		SubjectToken:     subjectTokenResponse.AccessToken,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		// Not specifying scope, should use intersection of subject and client scopes
	}

	response, err := authService.TokenExchange(ctx, req)
	if err != nil {
		t.Errorf("Expected successful token exchange with scope downgrade, got error: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}
	if response.Scope != "read" {
		t.Errorf("Expected scope 'read' (downgraded), got '%s'", response.Scope)
	}
}