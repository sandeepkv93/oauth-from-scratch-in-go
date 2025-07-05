package tests

import (
	"context"
	"strings"
	"testing"
	"time"

	"oauth-server/internal/dcr"
	"oauth-server/internal/scopes"
)

func TestDCRService_RegisterClient(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled:  true,
		DefaultScopes:        []string{"openid", "profile"},
		DefaultGrantTypes:    []string{"authorization_code", "refresh_token"},
		DefaultResponseTypes: []string{"code"},
		BaseURL:             "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	// Test basic client registration
	req := &dcr.ClientRegistrationRequest{
		ClientName:    "Test Application",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scope:         "openid profile",
	}

	response, err := dcrService.RegisterClient(ctx, req)
	if err != nil {
		t.Errorf("Expected successful client registration, got error: %v", err)
		return
	}

	// Verify response
	if response.ClientID == "" {
		t.Error("Expected non-empty client ID")
	}
	if response.ClientSecret == "" {
		t.Error("Expected non-empty client secret")
	}
	if response.RegistrationAccessToken == "" {
		t.Error("Expected non-empty registration access token")
	}
	if response.RegistrationClientURI == "" {
		t.Error("Expected non-empty registration client URI")
	}
	if response.ClientName != req.ClientName {
		t.Errorf("Expected client name '%s', got '%s'", req.ClientName, response.ClientName)
	}
	if len(response.RedirectURIs) != 1 || response.RedirectURIs[0] != req.RedirectURIs[0] {
		t.Errorf("Expected redirect URIs %v, got %v", req.RedirectURIs, response.RedirectURIs)
	}
	if response.Scope != req.Scope {
		t.Errorf("Expected scope '%s', got '%s'", req.Scope, response.Scope)
	}
}

func TestDCRService_RegisterClientDisabled(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled: false, // Disabled
		BaseURL:            "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	req := &dcr.ClientRegistrationRequest{
		ClientName:   "Test Application",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}

	_, err := dcrService.RegisterClient(ctx, req)
	if err != dcr.ErrAccessDenied {
		t.Errorf("Expected ErrAccessDenied when registration is disabled, got: %v", err)
	}
}

func TestDCRService_RegisterPublicClient(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled:  true,
		DefaultScopes:        []string{"openid", "profile"},
		DefaultGrantTypes:    []string{"authorization_code", "refresh_token"},
		DefaultResponseTypes: []string{"code"},
		BaseURL:             "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	// Test native/public client registration
	req := &dcr.ClientRegistrationRequest{
		ClientName:              "Mobile App",
		RedirectURIs:            []string{"com.example.app://callback"},
		ApplicationType:         "native",
		TokenEndpointAuthMethod: "none",
	}

	response, err := dcrService.RegisterClient(ctx, req)
	if err != nil {
		t.Errorf("Expected successful public client registration, got error: %v", err)
		return
	}

	// Public clients should not receive a client secret
	if response.ClientSecret != "" {
		t.Error("Expected empty client secret for public client")
	}
	if response.TokenEndpointAuthMethod != "none" {
		t.Errorf("Expected token endpoint auth method 'none', got '%s'", response.TokenEndpointAuthMethod)
	}
}

func TestDCRService_RegisterClientWithInvalidRedirectURI(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled: true,
		BaseURL:            "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	// Test with invalid redirect URI (contains fragment)
	req := &dcr.ClientRegistrationRequest{
		ClientName:   "Test Application",
		RedirectURIs: []string{"https://app.example.com/callback#fragment"},
	}

	_, err := dcrService.RegisterClient(ctx, req)
	if err == nil {
		t.Error("Expected error for redirect URI with fragment")
	}
	// Check if the error contains the expected error type (it's wrapped with additional context)
	if !strings.Contains(err.Error(), "invalid_redirect_uri") {
		t.Errorf("Expected error containing 'invalid_redirect_uri', got: %v", err)
	}
}

func TestDCRService_RegisterClientWithSecretExpiration(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled:  true,
		DefaultScopes:        []string{"openid"},
		DefaultGrantTypes:    []string{"authorization_code"},
		DefaultResponseTypes: []string{"code"},
		MaxSecretLifetime:    24 * time.Hour, // 1 day
		BaseURL:             "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	req := &dcr.ClientRegistrationRequest{
		ClientName:   "Test Application",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}

	response, err := dcrService.RegisterClient(ctx, req)
	if err != nil {
		t.Errorf("Expected successful client registration, got error: %v", err)
		return
	}

	// Should have client secret expiration
	if response.ClientSecretExpiresAt == 0 {
		t.Error("Expected client secret expiration to be set")
	}

	// Verify expiration is approximately 1 day from now
	expectedExpiration := time.Now().Add(24 * time.Hour).Unix()
	if response.ClientSecretExpiresAt < expectedExpiration-60 || response.ClientSecretExpiresAt > expectedExpiration+60 {
		t.Error("Client secret expiration is not within expected range")
	}
}

func TestDCRService_GetClient(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled:  true,
		DefaultScopes:        []string{"openid", "profile"},
		DefaultGrantTypes:    []string{"authorization_code"},
		DefaultResponseTypes: []string{"code"},
		BaseURL:             "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	// First register a client
	req := &dcr.ClientRegistrationRequest{
		ClientName:   "Test Application",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}

	registerResponse, err := dcrService.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	// Now retrieve the client
	getResponse, err := dcrService.GetClient(ctx, registerResponse.ClientID, registerResponse.RegistrationAccessToken)
	if err != nil {
		t.Errorf("Expected successful client retrieval, got error: %v", err)
		return
	}

	// Verify response matches
	if getResponse.ClientID != registerResponse.ClientID {
		t.Errorf("Expected client ID '%s', got '%s'", registerResponse.ClientID, getResponse.ClientID)
	}
	if getResponse.ClientName != registerResponse.ClientName {
		t.Errorf("Expected client name '%s', got '%s'", registerResponse.ClientName, getResponse.ClientName)
	}
	if getResponse.RegistrationAccessToken != registerResponse.RegistrationAccessToken {
		t.Errorf("Expected registration token '%s', got '%s'", registerResponse.RegistrationAccessToken, getResponse.RegistrationAccessToken)
	}
}

func TestDCRService_GetClientWithInvalidToken(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled: true,
		BaseURL:            "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	_, err := dcrService.GetClient(ctx, "invalid-client-id", "invalid-token")
	if err != dcr.ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken for invalid registration token, got: %v", err)
	}
}

func TestDCRService_UpdateClient(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled:  true,
		DefaultScopes:        []string{"openid", "profile"},
		DefaultGrantTypes:    []string{"authorization_code"},
		DefaultResponseTypes: []string{"code"},
		BaseURL:             "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	// First register a client
	req := &dcr.ClientRegistrationRequest{
		ClientName:   "Test Application",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}

	registerResponse, err := dcrService.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	// Update the client
	updateReq := &dcr.ClientRegistrationRequest{
		ClientName:   "Updated Application",
		RedirectURIs: []string{"https://app.example.com/callback", "https://app.example.com/callback2"},
		ClientURI:    "https://app.example.com",
	}

	updateResponse, err := dcrService.UpdateClient(ctx, registerResponse.ClientID, registerResponse.RegistrationAccessToken, updateReq)
	if err != nil {
		t.Errorf("Expected successful client update, got error: %v", err)
		return
	}

	// Verify updates
	if updateResponse.ClientName != updateReq.ClientName {
		t.Errorf("Expected updated client name '%s', got '%s'", updateReq.ClientName, updateResponse.ClientName)
	}
	if len(updateResponse.RedirectURIs) != 2 {
		t.Errorf("Expected 2 redirect URIs, got %d", len(updateResponse.RedirectURIs))
	}
	if updateResponse.ClientURI != updateReq.ClientURI {
		t.Errorf("Expected client URI '%s', got '%s'", updateReq.ClientURI, updateResponse.ClientURI)
	}
	
	// Client ID and registration token should remain the same
	if updateResponse.ClientID != registerResponse.ClientID {
		t.Error("Client ID should not change during update")
	}
	if updateResponse.RegistrationAccessToken != registerResponse.RegistrationAccessToken {
		t.Error("Registration access token should not change during update")
	}
}

func TestDCRService_DeleteClient(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled: true,
		BaseURL:            "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	// First register a client
	req := &dcr.ClientRegistrationRequest{
		ClientName:   "Test Application",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}

	registerResponse, err := dcrService.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	// Delete the client
	err = dcrService.DeleteClient(ctx, registerResponse.ClientID, registerResponse.RegistrationAccessToken)
	if err != nil {
		t.Errorf("Expected successful client deletion, got error: %v", err)
	}

	// Verify client is deleted - trying to get it should fail
	_, err = dcrService.GetClient(ctx, registerResponse.ClientID, registerResponse.RegistrationAccessToken)
	if err != dcr.ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken after deletion, got: %v", err)
	}
}

func TestDCRService_DeleteClientWithInvalidToken(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled: true,
		BaseURL:            "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	err := dcrService.DeleteClient(ctx, "invalid-client-id", "invalid-token")
	if err != dcr.ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken for invalid registration token, got: %v", err)
	}
}

func TestDCRService_ValidateRedirectURI(t *testing.T) {
	mockDB := NewMockDatabase()
	scopeService := scopes.NewService(mockDB)
	
	config := &dcr.Config{
		RegistrationEnabled: true,
		BaseURL:            "https://oauth.example.com",
	}
	
	dcrService := dcr.NewService(mockDB, scopeService, config)
	ctx := context.Background()

	testCases := []struct {
		name        string
		redirectURI string
		expectError bool
	}{
		{
			name:        "Valid HTTPS URI",
			redirectURI: "https://app.example.com/callback",
			expectError: false,
		},
		{
			name:        "Valid HTTP localhost URI",
			redirectURI: "http://localhost:8080/callback",
			expectError: false,
		},
		{
			name:        "Valid custom scheme (native app)",
			redirectURI: "com.example.app://callback",
			expectError: false,
		},
		{
			name:        "Invalid URI with fragment",
			redirectURI: "https://app.example.com/callback#fragment",
			expectError: true,
		},
		{
			name:        "Invalid relative URI",
			redirectURI: "/callback",
			expectError: true,
		},
		{
			name:        "Invalid URI syntax",
			redirectURI: "not-a-uri",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &dcr.ClientRegistrationRequest{
				ClientName:   "Test Application",
				RedirectURIs: []string{tc.redirectURI},
			}

			_, err := dcrService.RegisterClient(ctx, req)
			if tc.expectError && err == nil {
				t.Errorf("Expected error for redirect URI '%s', but got none", tc.redirectURI)
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error for redirect URI '%s', but got: %v", tc.redirectURI, err)
			}
		})
	}
}