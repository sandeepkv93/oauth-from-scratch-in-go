package tests

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/auth"
	"oauth-server/internal/db"
)

func TestImplicitGrant(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a public client for implicit grant
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("public-client-secret"), bcrypt.DefaultCost)
	publicClient := &db.Client{
		ClientID:     "public-client",
		ClientSecret: string(hashedSecret),
		Name:         "Public SPA Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "email", "read"},
		GrantTypes:   []string{"implicit"},
		IsPublic:     true,
	}
	mockDB.CreateClient(ctx, publicClient)

	// Get a test user
	var testUser *db.User
	for _, user := range mockDB.users {
		testUser = user
		break
	}

	// Create authorize request for implicit grant
	req := &auth.AuthorizeRequest{
		ResponseType: "token",
		ClientID:     "public-client",
		RedirectURI:  "http://localhost:3000/callback",
		Scope:        "read profile",
		State:        "test-state",
		Nonce:        "test-nonce",
	}

	response, err := authService.ImplicitGrant(ctx, req, testUser.ID)
	if err != nil {
		t.Errorf("Expected successful implicit grant, got error: %v", err)
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
	if response.State != "test-state" {
		t.Errorf("Expected state 'test-state', got '%s'", response.State)
	}
	if response.ExpiresIn <= 0 {
		t.Error("Expected positive expires_in value")
	}

	// Verify token can be validated
	claims, err := authService.ValidateAccessToken(response.AccessToken)
	if err != nil {
		t.Errorf("Failed to validate access token: %v", err)
	}
	if claims.UserID != testUser.ID {
		t.Errorf("Expected user ID %s, got %s", testUser.ID, claims.UserID)
	}
	if claims.ClientID != "public-client" {
		t.Errorf("Expected client ID 'public-client', got '%s'", claims.ClientID)
	}
}

func TestImplicitGrantWithOpenID(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client for implicit grant with OpenID
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("oidc-client-secret"), bcrypt.DefaultCost)
	oidcClient := &db.Client{
		ClientID:     "oidc-implicit-client",
		ClientSecret: string(hashedSecret),
		Name:         "OIDC Implicit Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "email"},
		GrantTypes:   []string{"implicit"},
		IsPublic:     true,
	}
	mockDB.CreateClient(ctx, oidcClient)

	// Get a test user
	var testUser *db.User
	for _, user := range mockDB.users {
		testUser = user
		break
	}

	// Create authorize request with OpenID scope
	req := &auth.AuthorizeRequest{
		ResponseType: "token",
		ClientID:     "oidc-implicit-client",
		RedirectURI:  "http://localhost:3000/callback",
		Scope:        "openid profile email",
		State:        "oidc-state",
		Nonce:        "oidc-nonce",
	}

	response, err := authService.ImplicitGrant(ctx, req, testUser.ID)
	if err != nil {
		t.Errorf("Expected successful implicit grant, got error: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}

	// Should indicate ID token generation is needed
	if !response.GenerateIDToken {
		t.Error("Expected GenerateIDToken to be true for OpenID scope")
	}
	if response.Nonce != "oidc-nonce" {
		t.Errorf("Expected nonce 'oidc-nonce', got '%s'", response.Nonce)
	}
}

func TestImplicitGrantInvalidClient(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Get a test user
	var testUser *db.User
	for _, user := range mockDB.users {
		testUser = user
		break
	}

	req := &auth.AuthorizeRequest{
		ResponseType: "token",
		ClientID:     "invalid-client",
		RedirectURI:  "http://localhost:3000/callback",
		Scope:        "read",
		State:        "test-state",
	}

	_, err := authService.ImplicitGrant(ctx, req, testUser.ID)
	if err == nil {
		t.Error("Expected error for invalid client")
	}
}

func TestImplicitGrantUnsupportedGrantType(t *testing.T) {
	authService, mockDB := setupTestAuth()
	ctx := context.Background()

	// Create a client that doesn't support implicit grant
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("no-implicit-secret"), bcrypt.DefaultCost)
	noImplicitClient := &db.Client{
		ClientID:     "no-implicit-client",
		ClientSecret: string(hashedSecret),
		Name:         "No Implicit Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"authorization_code"}, // No implicit grant
		IsPublic:     false,
	}
	mockDB.CreateClient(ctx, noImplicitClient)

	// Get a test user
	var testUser *db.User
	for _, user := range mockDB.users {
		testUser = user
		break
	}

	req := &auth.AuthorizeRequest{
		ResponseType: "token",
		ClientID:     "no-implicit-client",
		RedirectURI:  "http://localhost:3000/callback",
		Scope:        "read",
		State:        "test-state",
	}

	_, err := authService.ImplicitGrant(ctx, req, testUser.ID)
	if err == nil {
		t.Error("Expected error for unsupported grant type")
	}
	if err != auth.ErrInvalidGrant {
		t.Errorf("Expected ErrInvalidGrant, got: %v", err)
	}
}

func TestCreateImplicitRedirectURL(t *testing.T) {
	authService, _ := setupTestAuth()

	response := &auth.ImplicitGrantResponse{
		AccessToken: "test_access_token_12345",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       "read write",
		State:       "test-state",
	}

	redirectURL := authService.CreateImplicitRedirectURL("http://localhost:3000/callback", response)

	// Check that it uses fragment (not query parameters)
	if !contains(redirectURL, "#access_token=") {
		t.Error("Expected redirect URL to contain access_token in fragment")
	}
	if !contains(redirectURL, "token_type=Bearer") {
		t.Error("Expected redirect URL to contain token_type in fragment")
	}
	if !contains(redirectURL, "expires_in=3600") {
		t.Error("Expected redirect URL to contain expires_in in fragment")
	}
	if !contains(redirectURL, "state=test-state") {
		t.Error("Expected redirect URL to contain state in fragment")
	}
	if !contains(redirectURL, "scope=read") {
		t.Errorf("Expected redirect URL to contain scope in fragment, got: %s", redirectURL)
	}

	// Should not have query parameters for tokens
	if contains(redirectURL, "?access_token=") {
		t.Error("Access token should not be in query parameters")
	}
}

func TestCreateImplicitRedirectURLWithIDToken(t *testing.T) {
	authService, _ := setupTestAuth()

	response := &auth.ImplicitGrantResponse{
		AccessToken: "test_access_token_12345",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       "openid profile",
		State:       "oidc-state",
		IDToken:     "eyJhbGciOiJIUzI1NiJ9.test.signature",
	}

	redirectURL := authService.CreateImplicitRedirectURL("http://localhost:3000/callback", response)

	if !contains(redirectURL, "#access_token=") {
		t.Error("Expected redirect URL to contain access_token in fragment")
	}
	if !contains(redirectURL, "id_token=") {
		t.Error("Expected redirect URL to contain id_token in fragment")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		 (len(s) > len(substr) && stringContains(s, substr)))))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}