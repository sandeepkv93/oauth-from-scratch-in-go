package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"oauth-server/pkg/jwt"
)

func TestJWTManagerCreation(t *testing.T) {
	secret := "test-secret"
	manager := jwt.NewManager(secret)

	if manager == nil {
		t.Fatal("JWT Manager should not be nil")
	}
}

func TestAccessTokenGeneration(t *testing.T) {
	manager := jwt.NewManager("test-secret")
	userID := uuid.New()
	clientID := "test-client"
	scopes := []string{"read", "write"}
	tokenID := uuid.New()
	ttl := 15 * time.Minute

	token, err := manager.GenerateAccessToken(userID, clientID, scopes, tokenID, ttl)
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	if len(token) < 10 {
		t.Error("Token should be reasonably long")
	}
}

func TestAccessTokenValidation(t *testing.T) {
	manager := jwt.NewManager("test-secret")
	userID := uuid.New()
	clientID := "test-client"
	scopes := []string{"read", "write"}
	tokenID := uuid.New()
	ttl := 15 * time.Minute

	token, err := manager.GenerateAccessToken(userID, clientID, scopes, tokenID, ttl)
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("Failed to validate access token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}

	if claims.ClientID != clientID {
		t.Errorf("Expected client ID %s, got %s", clientID, claims.ClientID)
	}

	if len(claims.Scopes) != len(scopes) {
		t.Errorf("Expected %d scopes, got %d", len(scopes), len(claims.Scopes))
	}

	for i, scope := range scopes {
		if i >= len(claims.Scopes) || claims.Scopes[i] != scope {
			t.Errorf("Expected scope %s at index %d, got %s", scope, i, claims.Scopes[i])
		}
	}

	if claims.TokenID != tokenID {
		t.Errorf("Expected token ID %s, got %s", tokenID, claims.TokenID)
	}
}

func TestAccessTokenValidationWithWrongSecret(t *testing.T) {
	manager1 := jwt.NewManager("secret1")
	manager2 := jwt.NewManager("secret2")

	userID := uuid.New()
	tokenID := uuid.New()

	token, err := manager1.GenerateAccessToken(userID, "client", []string{"read"}, tokenID, time.Minute)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = manager2.ValidateAccessToken(token)
	if err == nil {
		t.Error("Validation should fail with wrong secret")
	}
}

func TestRefreshTokenGeneration(t *testing.T) {
	manager := jwt.NewManager("test-secret")

	token1, err := manager.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("Failed to generate refresh token: %v", err)
	}

	token2, err := manager.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("Failed to generate second refresh token: %v", err)
	}

	if token1 == "" || token2 == "" {
		t.Error("Refresh tokens should not be empty")
	}

	if token1 == token2 {
		t.Error("Refresh tokens should be unique")
	}

	if len(token1) < 10 {
		t.Error("Refresh token should be reasonably long")
	}
}

func TestAuthorizationCodeGeneration(t *testing.T) {
	manager := jwt.NewManager("test-secret")

	code1, err := manager.GenerateAuthorizationCode()
	if err != nil {
		t.Fatalf("Failed to generate authorization code: %v", err)
	}

	code2, err := manager.GenerateAuthorizationCode()
	if err != nil {
		t.Fatalf("Failed to generate second authorization code: %v", err)
	}

	if code1 == "" || code2 == "" {
		t.Error("Authorization codes should not be empty")
	}

	if code1 == code2 {
		t.Error("Authorization codes should be unique")
	}

	if len(code1) < 10 {
		t.Error("Authorization code should be reasonably long")
	}
}

func TestClientSecretGeneration(t *testing.T) {
	manager := jwt.NewManager("test-secret")

	secret1, err := manager.GenerateClientSecret()
	if err != nil {
		t.Fatalf("Failed to generate client secret: %v", err)
	}

	secret2, err := manager.GenerateClientSecret()
	if err != nil {
		t.Fatalf("Failed to generate second client secret: %v", err)
	}

	if secret1 == "" || secret2 == "" {
		t.Error("Client secrets should not be empty")
	}

	if secret1 == secret2 {
		t.Error("Client secrets should be unique")
	}

	if len(secret1) < 10 {
		t.Error("Client secret should be reasonably long")
	}
}

func TestExpiredTokenValidation(t *testing.T) {
	manager := jwt.NewManager("test-secret")
	userID := uuid.New()
	tokenID := uuid.New()

	token, err := manager.GenerateAccessToken(userID, "client", []string{"read"}, tokenID, -time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	_, err = manager.ValidateAccessToken(token)
	if err == nil {
		t.Error("Validation should fail for expired token")
	}
}

func TestInvalidTokenValidation(t *testing.T) {
	manager := jwt.NewManager("test-secret")

	_, err := manager.ValidateAccessToken("invalid-token")
	if err == nil {
		t.Error("Validation should fail for invalid token")
	}

	_, err = manager.ValidateAccessToken("")
	if err == nil {
		t.Error("Validation should fail for empty token")
	}

	_, err = manager.ValidateAccessToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature")
	if err == nil {
		t.Error("Validation should fail for malformed token")
	}
}

func TestTokenClaims(t *testing.T) {
	manager := jwt.NewManager("test-secret")
	userID := uuid.New()
	clientID := "test-client"
	scopes := []string{"openid", "profile", "email"}
	tokenID := uuid.New()
	ttl := 30 * time.Minute

	token, err := manager.GenerateAccessToken(userID, clientID, scopes, tokenID, ttl)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.Issuer != "oauth-server" {
		t.Errorf("Expected issuer 'oauth-server', got %s", claims.Issuer)
	}

	if claims.Subject != userID.String() {
		t.Errorf("Expected subject %s, got %s", userID.String(), claims.Subject)
	}

	if len(claims.Audience) != 1 || claims.Audience[0] != clientID {
		t.Errorf("Expected audience [%s], got %v", clientID, claims.Audience)
	}

	if claims.ID != tokenID.String() {
		t.Errorf("Expected ID %s, got %s", tokenID.String(), claims.ID)
	}

	if claims.IssuedAt == nil {
		t.Error("IssuedAt should not be nil")
	}

	if claims.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	}

	if claims.NotBefore == nil {
		t.Error("NotBefore should not be nil")
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		t.Error("Token should not be expired")
	}
}

func TestEmptyScopes(t *testing.T) {
	manager := jwt.NewManager("test-secret")
	userID := uuid.New()
	tokenID := uuid.New()

	token, err := manager.GenerateAccessToken(userID, "client", []string{}, tokenID, time.Minute)
	if err != nil {
		t.Fatalf("Failed to generate token with empty scopes: %v", err)
	}

	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token with empty scopes: %v", err)
	}

	if len(claims.Scopes) != 0 {
		t.Errorf("Expected empty scopes, got %v", claims.Scopes)
	}
}