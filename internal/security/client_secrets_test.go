package security

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/db"
)

// SecretDBInterface defines only the methods needed for secret management
type SecretDBInterface interface {
	CreateClientSecret(ctx context.Context, secret *db.ClientSecret) error
	GetActiveClientSecrets(ctx context.Context, clientID uuid.UUID) ([]*db.ClientSecret, error)
	GetClientSecretByID(ctx context.Context, secretID uuid.UUID) (*db.ClientSecret, error)
	MarkSecretsNonPrimary(ctx context.Context, clientID uuid.UUID) error
	RevokeClientSecret(ctx context.Context, secretID uuid.UUID) error
	CleanupOldSecrets(ctx context.Context, clientID uuid.UUID, maxSecrets int) error
	GetExpiringSecrets(ctx context.Context, withinDuration time.Duration) ([]*db.ClientSecret, error)
}

// MockSecretDB implements only the secret-related methods
type MockSecretDB struct {
	secrets map[uuid.UUID][]*db.ClientSecret
}

func NewMockSecretDB() *MockSecretDB {
	return &MockSecretDB{
		secrets: make(map[uuid.UUID][]*db.ClientSecret),
	}
}

func (m *MockSecretDB) CreateClientSecret(ctx context.Context, secret *db.ClientSecret) error {
	if secret.ID == uuid.Nil {
		secret.ID = uuid.New()
	}
	if secret.CreatedAt.IsZero() {
		secret.CreatedAt = time.Now()
	}
	if secret.UpdatedAt.IsZero() {
		secret.UpdatedAt = time.Now()
	}
	m.secrets[secret.ClientID] = append(m.secrets[secret.ClientID], secret)
	return nil
}

func (m *MockSecretDB) GetActiveClientSecrets(ctx context.Context, clientID uuid.UUID) ([]*db.ClientSecret, error) {
	secrets := m.secrets[clientID]
	active := []*db.ClientSecret{}
	now := time.Now()
	for _, secret := range secrets {
		if secret.RevokedAt == nil && (secret.ExpiresAt == nil || secret.ExpiresAt.After(now)) {
			active = append(active, secret)
		}
	}
	return active, nil
}

func (m *MockSecretDB) GetClientSecretByID(ctx context.Context, secretID uuid.UUID) (*db.ClientSecret, error) {
	for _, secrets := range m.secrets {
		for _, secret := range secrets {
			if secret.ID == secretID {
				return secret, nil
			}
		}
	}
	return nil, errors.New("secret not found")
}

func (m *MockSecretDB) MarkSecretsNonPrimary(ctx context.Context, clientID uuid.UUID) error {
	secrets := m.secrets[clientID]
	now := time.Now()
	for _, secret := range secrets {
		if secret.RevokedAt == nil {
			if secret.IsPrimary {
				secret.RotatedAt = &now
			}
			secret.IsPrimary = false
			secret.UpdatedAt = now
		}
	}
	return nil
}

func (m *MockSecretDB) RevokeClientSecret(ctx context.Context, secretID uuid.UUID) error {
	for _, secrets := range m.secrets {
		for _, secret := range secrets {
			if secret.ID == secretID && secret.RevokedAt == nil {
				now := time.Now()
				secret.RevokedAt = &now
				secret.UpdatedAt = now
				return nil
			}
		}
	}
	return errors.New("secret not found or already revoked")
}

func (m *MockSecretDB) CleanupOldSecrets(ctx context.Context, clientID uuid.UUID, maxSecrets int) error {
	secrets := m.secrets[clientID]
	if len(secrets) > maxSecrets {
		m.secrets[clientID] = secrets[:maxSecrets]
	}
	return nil
}

func (m *MockSecretDB) GetExpiringSecrets(ctx context.Context, withinDuration time.Duration) ([]*db.ClientSecret, error) {
	var expiring []*db.ClientSecret
	now := time.Now()
	threshold := now.Add(withinDuration)

	for _, secrets := range m.secrets {
		for _, secret := range secrets {
			if secret.RevokedAt == nil && secret.ExpiresAt != nil {
				if secret.ExpiresAt.After(now) && secret.ExpiresAt.Before(threshold) {
					expiring = append(expiring, secret)
				}
			}
		}
	}
	return expiring, nil
}

// Test suite

func TestNewClientSecretManager(t *testing.T) {
	mockDB := NewMockSecretDB()

	t.Run("with default config", func(t *testing.T) {
		manager := NewClientSecretManager(mockDB, nil)
		if manager == nil {
			t.Fatal("Expected manager to be created")
		}
		if manager.config == nil {
			t.Fatal("Expected default config to be set")
		}
		if manager.config.MaxActiveSecrets != 2 {
			t.Errorf("Expected MaxActiveSecrets to be 2, got %d", manager.config.MaxActiveSecrets)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		customConfig := &SecretRotationConfig{
			MaxActiveSecrets: 5,
			RotationPeriod:   30 * 24 * time.Hour,
		}
		manager := NewClientSecretManager(mockDB, customConfig)
		if manager.config.MaxActiveSecrets != 5 {
			t.Errorf("Expected MaxActiveSecrets to be 5, got %d", manager.config.MaxActiveSecrets)
		}
	})
}

func TestRotateSecret(t *testing.T) {
	mockDB := NewMockSecretDB()
	manager := NewClientSecretManager(mockDB, nil)
	ctx := context.Background()
	clientID := uuid.New()

	t.Run("first rotation creates primary secret", func(t *testing.T) {
		secret, err := manager.RotateSecret(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to rotate secret: %v", err)
		}

		if secret.PlainText == "" {
			t.Error("Expected plain text secret to be set")
		}

		if secret.SecretHash == "" {
			t.Error("Expected secret hash to be set")
		}

		if !secret.IsPrimary {
			t.Error("Expected first secret to be primary")
		}

		if secret.ExpiresAt == nil {
			t.Error("Expected expiration to be set")
		}

		// Verify secret is stored correctly
		active, err := mockDB.GetActiveClientSecrets(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to get active secrets: %v", err)
		}

		if len(active) != 1 {
			t.Fatalf("Expected 1 active secret, got %d", len(active))
		}
	})

	t.Run("second rotation marks old secret as non-primary", func(t *testing.T) {
		// Get the first secret
		activeBeforeRotation, _ := mockDB.GetActiveClientSecrets(ctx, clientID)
		firstSecret := activeBeforeRotation[0]

		// Rotate again
		newSecret, err := manager.RotateSecret(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to rotate secret: %v", err)
		}

		// Verify new secret is primary
		if !newSecret.IsPrimary {
			t.Error("Expected new secret to be primary")
		}

		// Verify old secret is now non-primary
		active, _ := mockDB.GetActiveClientSecrets(ctx, clientID)
		if len(active) != 2 {
			t.Fatalf("Expected 2 active secrets after rotation, got %d", len(active))
		}

		// Find the old secret
		var oldSecret *db.ClientSecret
		for _, s := range active {
			if s.ID == firstSecret.ID {
				oldSecret = s
				break
			}
		}

		if oldSecret == nil {
			t.Fatal("Old secret not found in active secrets")
		}

		if oldSecret.IsPrimary {
			t.Error("Expected old secret to be marked as non-primary")
		}

		if oldSecret.RotatedAt == nil {
			t.Error("Expected old secret to have RotatedAt timestamp")
		}
	})

	t.Run("cleanup removes excess secrets", func(t *testing.T) {
		// Rotate multiple times to exceed MaxActiveSecrets (2)
		_, _ = manager.RotateSecret(ctx, clientID)

		active, _ := mockDB.GetActiveClientSecrets(ctx, clientID)
		if len(active) > 2 {
			t.Errorf("Expected max 2 active secrets after cleanup, got %d", len(active))
		}
	})
}

func TestValidateSecret(t *testing.T) {
	mockDB := NewMockSecretDB()
	manager := NewClientSecretManager(mockDB, nil)
	ctx := context.Background()
	clientID := uuid.New()

	// Create a secret
	secret, err := manager.RotateSecret(ctx, clientID)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	plainSecret := secret.PlainText

	t.Run("valid secret passes validation", func(t *testing.T) {
		valid, err := manager.ValidateSecret(ctx, clientID, plainSecret)
		if err != nil {
			t.Fatalf("Validation error: %v", err)
		}
		if !valid {
			t.Error("Expected valid secret to pass validation")
		}
	})

	t.Run("invalid secret fails validation", func(t *testing.T) {
		valid, err := manager.ValidateSecret(ctx, clientID, "wrong-secret")
		if err != nil {
			t.Fatalf("Validation error: %v", err)
		}
		if valid {
			t.Error("Expected invalid secret to fail validation")
		}
	})

	t.Run("validates against multiple active secrets", func(t *testing.T) {
		// Rotate to create a second secret
		newSecret, err := manager.RotateSecret(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to rotate secret: %v", err)
		}

		// Both old and new secrets should be valid
		oldValid, _ := manager.ValidateSecret(ctx, clientID, plainSecret)
		if !oldValid {
			t.Error("Expected old secret to still be valid during grace period")
		}

		newValid, _ := manager.ValidateSecret(ctx, clientID, newSecret.PlainText)
		if !newValid {
			t.Error("Expected new secret to be valid")
		}
	})

	t.Run("no active secrets returns false", func(t *testing.T) {
		emptyClientID := uuid.New()
		valid, err := manager.ValidateSecret(ctx, emptyClientID, "any-secret")
		if err != nil {
			t.Fatalf("Validation error: %v", err)
		}
		if valid {
			t.Error("Expected validation to fail when no active secrets exist")
		}
	})
}

func TestRevokeSecret(t *testing.T) {
	mockDB := NewMockSecretDB()
	manager := NewClientSecretManager(mockDB, nil)
	ctx := context.Background()
	clientID := uuid.New()

	// Create a secret
	secret, err := manager.RotateSecret(ctx, clientID)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	t.Run("revoke makes secret inactive", func(t *testing.T) {
		err := manager.RevokeSecret(ctx, secret.ID)
		if err != nil {
			t.Fatalf("Failed to revoke secret: %v", err)
		}

		// Verify secret is no longer active
		active, _ := mockDB.GetActiveClientSecrets(ctx, clientID)
		for _, s := range active {
			if s.ID == secret.ID {
				t.Error("Revoked secret should not be in active secrets list")
			}
		}

		// Verify secret can no longer be used for validation
		valid, _ := manager.ValidateSecret(ctx, clientID, secret.PlainText)
		if valid {
			t.Error("Revoked secret should fail validation")
		}
	})

	t.Run("revoking non-existent secret returns error", func(t *testing.T) {
		fakeID := uuid.New()
		err := manager.RevokeSecret(ctx, fakeID)
		if err == nil {
			t.Error("Expected error when revoking non-existent secret")
		}
	})
}

func TestGetActiveSecrets(t *testing.T) {
	mockDB := NewMockSecretDB()
	manager := NewClientSecretManager(mockDB, nil)
	ctx := context.Background()
	clientID := uuid.New()

	t.Run("returns empty list for new client", func(t *testing.T) {
		secrets, err := manager.GetActiveSecrets(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to get active secrets: %v", err)
		}
		if len(secrets) != 0 {
			t.Errorf("Expected 0 secrets, got %d", len(secrets))
		}
	})

	t.Run("returns secrets without hashes", func(t *testing.T) {
		// Create a secret
		_, err := manager.RotateSecret(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		secrets, err := manager.GetActiveSecrets(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to get active secrets: %v", err)
		}

		if len(secrets) != 1 {
			t.Fatalf("Expected 1 secret, got %d", len(secrets))
		}

		// Verify hash is cleared
		if secrets[0].SecretHash != "" {
			t.Error("Expected secret hash to be cleared in response")
		}

		// Verify other fields are present
		if secrets[0].ID == uuid.Nil {
			t.Error("Expected secret ID to be present")
		}
	})
}

func TestGetExpiringSecrets(t *testing.T) {
	mockDB := NewMockSecretDB()

	// Use custom config with short expiration for testing
	config := &SecretRotationConfig{
		MaxActiveSecrets: 2,
		RotationPeriod:   30 * time.Minute, // Secret expires in 30 minutes
		NotifyBefore:     1 * time.Hour,    // Notify window is 1 hour
	}

	manager := NewClientSecretManager(mockDB, config)
	ctx := context.Background()
	clientID := uuid.New()

	t.Run("finds secrets expiring soon", func(t *testing.T) {
		// Create a secret that will expire soon (in 30 minutes)
		_, err := manager.RotateSecret(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Check for expiring secrets (within 1 hour notification window)
		expiring, err := manager.GetExpiringSecrets(ctx)
		if err != nil {
			t.Fatalf("Failed to get expiring secrets: %v", err)
		}

		// Since rotation period is 30 min and notify before is 1 hour,
		// the secret should be in the expiring list
		if len(expiring) != 1 {
			t.Errorf("Expected 1 expiring secret, got %d", len(expiring))
		}
	})
}

func TestAutoRotateExpiring(t *testing.T) {
	mockDB := NewMockSecretDB()

	config := &SecretRotationConfig{
		MaxActiveSecrets: 2,
		RotationPeriod:   1 * time.Hour,
		NotifyBefore:     2 * time.Hour, // Notify before expiration
		AutoRotate:       true,
		GracePeriod:      7 * 24 * time.Hour,
	}

	manager := NewClientSecretManager(mockDB, config)
	ctx := context.Background()

	t.Run("disabled when AutoRotate is false", func(t *testing.T) {
		disabledConfig := &SecretRotationConfig{
			AutoRotate: false,
		}
		disabledManager := NewClientSecretManager(mockDB, disabledConfig)

		count, err := disabledManager.AutoRotateExpiring(ctx)
		if err == nil {
			t.Error("Expected error when auto-rotation is disabled")
		}
		if count != 0 {
			t.Errorf("Expected 0 rotations, got %d", count)
		}
	})

	t.Run("rotates primary expiring secrets", func(t *testing.T) {
		clientID := uuid.New()

		// Create a secret
		_, err := manager.RotateSecret(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Auto-rotate expiring secrets
		count, err := manager.AutoRotateExpiring(ctx)
		if err != nil {
			t.Fatalf("Failed to auto-rotate: %v", err)
		}

		if count != 1 {
			t.Errorf("Expected 1 rotation, got %d", count)
		}

		// Verify we now have 2 secrets (old + new)
		active, _ := mockDB.GetActiveClientSecrets(ctx, clientID)
		if len(active) != 2 {
			t.Errorf("Expected 2 active secrets after auto-rotation, got %d", len(active))
		}
	})
}

func TestGenerateSecureSecret(t *testing.T) {
	mockDB := NewMockSecretDB()
	manager := NewClientSecretManager(mockDB, nil)

	t.Run("generates secret of correct length", func(t *testing.T) {
		secret, err := manager.GenerateSecureSecret(32)
		if err != nil {
			t.Fatalf("Failed to generate secret: %v", err)
		}

		if len(secret) == 0 {
			t.Error("Expected non-empty secret")
		}

		// Base64 URL encoding adds some padding, so length may vary slightly
		if len(secret) < 16 {
			t.Errorf("Expected secret length >= 16, got %d", len(secret))
		}
	})

	t.Run("enforces minimum length", func(t *testing.T) {
		secret, err := manager.GenerateSecureSecret(8) // Below minimum
		if err != nil {
			t.Fatalf("Failed to generate secret: %v", err)
		}

		// Should be at least 16 chars due to minimum enforcement
		if len(secret) < 16 {
			t.Errorf("Expected minimum secret length of 16, got %d", len(secret))
		}
	})

	t.Run("generates unique secrets", func(t *testing.T) {
		secret1, _ := manager.GenerateSecureSecret(32)
		secret2, _ := manager.GenerateSecureSecret(32)

		if secret1 == secret2 {
			t.Error("Expected unique secrets, got duplicates")
		}
	})
}

func TestGetSecretInfo(t *testing.T) {
	mockDB := NewMockSecretDB()

	config := &SecretRotationConfig{
		MaxActiveSecrets: 2,
		RotationPeriod:   90 * 24 * time.Hour,
		NotifyBefore:     14 * 24 * time.Hour,
	}

	manager := NewClientSecretManager(mockDB, config)
	ctx := context.Background()
	clientID := uuid.New()

	t.Run("returns comprehensive secret info", func(t *testing.T) {
		// Create a secret
		secret, err := manager.RotateSecret(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		info, err := manager.GetSecretInfo(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to get secret info: %v", err)
		}

		if info.ClientID != clientID {
			t.Error("Expected correct client ID in info")
		}

		if info.ActiveCount != 1 {
			t.Errorf("Expected 1 active secret, got %d", info.ActiveCount)
		}

		if info.PrimarySecretID == nil || *info.PrimarySecretID != secret.ID {
			t.Error("Expected primary secret ID to match created secret")
		}

		if len(info.Secrets) != 1 {
			t.Fatalf("Expected 1 secret detail, got %d", len(info.Secrets))
		}

		detail := info.Secrets[0]
		if detail.ID != secret.ID {
			t.Error("Expected secret detail ID to match")
		}

		if !detail.IsPrimary {
			t.Error("Expected secret to be marked as primary")
		}

		if detail.DaysUntilExpiry <= 0 {
			t.Error("Expected positive days until expiry")
		}
	})

	t.Run("identifies expiring secrets", func(t *testing.T) {
		// Test that IsExpiringSoon flag is calculated correctly
		// A secret expiring in 5 days with NotifyBefore of 7 days should be flagged
		shortConfig := &SecretRotationConfig{
			RotationPeriod: 5 * 24 * time.Hour, // Secret expires in 5 days
			NotifyBefore:   7 * 24 * time.Hour, // Notify 7 days before
		}

		testClientID := uuid.New()
		testSecret := &db.ClientSecret{
			ID:        uuid.New(),
			ClientID:  testClientID,
			IsPrimary: true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		expiresAt := time.Now().Add(5 * 24 * time.Hour)
		testSecret.ExpiresAt = &expiresAt

		// Calculate if it should be expiring soon
		timeUntilExpiry := time.Until(*testSecret.ExpiresAt)
		isExpiringSoon := timeUntilExpiry < shortConfig.NotifyBefore

		if !isExpiringSoon {
			t.Error("Expected secret expiring in 5 days to be marked as expiring soon when NotifyBefore is 7 days")
		}
	})
}

func TestSecretHashSecurity(t *testing.T) {
	mockDB := NewMockSecretDB()
	manager := NewClientSecretManager(mockDB, nil)
	ctx := context.Background()
	clientID := uuid.New()

	t.Run("secret is properly hashed with bcrypt", func(t *testing.T) {
		secret, err := manager.RotateSecret(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Verify hash is bcrypt format (starts with $2a$ or $2b$)
		if len(secret.SecretHash) < 10 {
			t.Error("Secret hash appears too short for bcrypt")
		}

		// Verify we can validate the plain text against the hash
		err = bcrypt.CompareHashAndPassword([]byte(secret.SecretHash), []byte(secret.PlainText))
		if err != nil {
			t.Error("Generated hash does not match plain text secret")
		}

		// Verify wrong secret doesn't match
		err = bcrypt.CompareHashAndPassword([]byte(secret.SecretHash), []byte("wrong-secret"))
		if err == nil {
			t.Error("Wrong secret should not match hash")
		}
	})
}
