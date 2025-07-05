package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"oauth-server/internal/auth"
	"oauth-server/pkg/jwt"
)


func TestAuthenticateUser(t *testing.T) {
	authService, _ := SetupTestAuth()
	ctx := context.Background()

	user, err := authService.AuthenticateUser(ctx, "testuser", "testpassword")
	if err != nil {
		t.Errorf("Expected successful authentication, got error: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	_, err = authService.AuthenticateUser(ctx, "testuser", "wrongpassword")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestValidateClient(t *testing.T) {
	authService, _ := SetupTestAuth()
	ctx := context.Background()

	client, err := authService.ValidateClient(ctx, "test-client", "test-secret")
	if err != nil {
		t.Errorf("Expected successful client validation, got error: %v", err)
	}
	if client.ClientID != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%s'", client.ClientID)
	}

	_, err = authService.ValidateClient(ctx, "test-client", "wrong-secret")
	if err != auth.ErrInvalidClient {
		t.Errorf("Expected ErrInvalidClient, got: %v", err)
	}

	_, err = authService.ValidateClient(ctx, "invalid-client", "test-secret")
	if err != auth.ErrInvalidClient {
		t.Errorf("Expected ErrInvalidClient, got: %v", err)
	}
}

func TestCreateAuthorizationCode(t *testing.T) {
	authService, mockDb := SetupTestAuth()
	ctx := context.Background()

	userID := uuid.New()
	for _, user := range mockDb.users {
		userID = user.ID
		break
	}

	code, err := authService.CreateAuthorizationCode(
		ctx,
		userID,
		"test-client",
		"http://localhost:8080/callback",
		[]string{"openid", "profile"},
		"",
		"",
	)

	if err != nil {
		t.Errorf("Expected successful code creation, got error: %v", err)
	}
	if code == "" {
		t.Error("Expected non-empty authorization code")
	}

	authCode, exists := mockDb.codes[code]
	if !exists {
		t.Error("Authorization code not found in database")
	}
	if authCode.ClientID != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%s'", authCode.ClientID)
	}
}

func TestClientCredentialsGrant(t *testing.T) {
	authService, mockDB := SetupTestAuth()
	ctx := context.Background()

	// Verify client exists and has correct scopes
	client, err := mockDB.GetClientByID(ctx, "test-client")
	if err != nil {
		t.Fatalf("Failed to get test client: %v", err)
	}
	t.Logf("Client scopes: %v", client.Scopes)

	req := &auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read write",
	}

	// Debug scope validation
	scopes := []string{"read", "write"}
	validateErr := authService.ValidateScopes(ctx, scopes, client.Scopes)
	t.Logf("Scope validation error: %v", validateErr)

	response, err := authService.ClientCredentialsGrant(ctx, req)
	if err != nil {
		t.Errorf("Expected successful client credentials grant, got error: %v", err)
		return
	}
	if response == nil {
		t.Error("Expected non-nil response")
		return
	}
	if response.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}
	if response.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", response.TokenType)
	}
}

func TestValidateScopes(t *testing.T) {
	authService, _ := SetupTestAuth()
	ctx := context.Background()

	allowedScopes := []string{"openid", "profile", "email", "read"}

	err := authService.ValidateScopes(ctx, []string{"openid", "profile"}, allowedScopes)
	if err != nil {
		t.Errorf("Expected valid scopes, got error: %v", err)
	}

	err = authService.ValidateScopes(ctx, []string{"openid", "admin"}, allowedScopes)
	if err != auth.ErrInvalidScope {
		t.Errorf("Expected ErrInvalidScope, got: %v", err)
	}
}

func TestJWTTokenGeneration(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")

	userID := uuid.New()
	clientID := "test-client"
	scopes := []string{"openid", "profile"}
	tokenID := uuid.New()
	ttl := 15 * time.Minute

	token, err := jwtManager.GenerateAccessToken(userID, clientID, scopes, tokenID, ttl)
	if err != nil {
		t.Errorf("Expected successful token generation, got error: %v", err)
	}
	if token == "" {
		t.Error("Expected non-empty token")
	}

	claims, err := jwtManager.ValidateAccessToken(token)
	if err != nil {
		t.Errorf("Expected successful token validation, got error: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("Expected user_id '%s', got '%s'", userID, claims.UserID)
	}
	if claims.ClientID != clientID {
		t.Errorf("Expected client_id '%s', got '%s'", clientID, claims.ClientID)
	}
}