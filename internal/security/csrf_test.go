package security

import (
	"testing"
	"time"
)

func TestCSRFManager_GenerateToken(t *testing.T) {
	manager := NewCSRFManager("test-secret-key", 24*time.Hour)

	token, err := manager.GenerateToken("session-123")
	if err != nil {
		t.Fatalf("Failed to generate CSRF token: %v", err)
	}

	if token == "" {
		t.Error("Generated token should not be empty")
	}
}

func TestCSRFManager_ValidateToken_Success(t *testing.T) {
	manager := NewCSRFManager("test-secret-key", 24*time.Hour)
	sessionID := "session-123"

	token, err := manager.GenerateToken(sessionID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	err = manager.ValidateToken(token, sessionID)
	if err != nil {
		t.Errorf("Token validation failed: %v", err)
	}
}

func TestCSRFManager_ValidateToken_WrongSession(t *testing.T) {
	manager := NewCSRFManager("test-secret-key", 24*time.Hour)

	token, _ := manager.GenerateToken("session-123")

	err := manager.ValidateToken(token, "session-456")
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got: %v", err)
	}
}

func TestCSRFManager_ValidateToken_Expired(t *testing.T) {
	manager := NewCSRFManager("test-secret-key", 1*time.Millisecond)
	sessionID := "session-123"

	token, err := manager.GenerateToken(sessionID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	err = manager.ValidateToken(token, sessionID)
	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got: %v", err)
	}
}

func TestCSRFManager_ValidateToken_InvalidFormat(t *testing.T) {
	manager := NewCSRFManager("test-secret-key", 24*time.Hour)

	tests := []struct {
		name  string
		token string
	}{
		{"Empty token", ""},
		{"Random string", "not-a-valid-token"},
		{"Invalid base64", "!!!invalid!!!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.ValidateToken(tt.token, "session-123")
			if err == nil {
				t.Error("Expected validation to fail for invalid token")
			}
		})
	}
}

func TestCSRFManager_ValidateToken_WrongSecret(t *testing.T) {
	manager1 := NewCSRFManager("secret-1", 24*time.Hour)
	manager2 := NewCSRFManager("secret-2", 24*time.Hour)

	sessionID := "session-123"
	token, _ := manager1.GenerateToken(sessionID)

	// Try to validate with different secret
	err := manager2.ValidateToken(token, sessionID)
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken when using wrong secret, got: %v", err)
	}
}

func TestCSRFManager_TokenUniqueness(t *testing.T) {
	manager := NewCSRFManager("test-secret-key", 24*time.Hour)
	sessionID := "session-123"

	// Generate multiple tokens for same session
	token1, _ := manager.GenerateToken(sessionID)
	token2, _ := manager.GenerateToken(sessionID)

	if token1 == token2 {
		t.Error("Generated tokens should be unique even for same session")
	}

	// Both tokens should be valid
	if err := manager.ValidateToken(token1, sessionID); err != nil {
		t.Errorf("Token 1 should be valid: %v", err)
	}

	if err := manager.ValidateToken(token2, sessionID); err != nil {
		t.Errorf("Token 2 should be valid: %v", err)
	}
}
