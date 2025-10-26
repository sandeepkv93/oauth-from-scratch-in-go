package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/db"
)

// SecretRotationConfig defines configuration for secret rotation
type SecretRotationConfig struct {
	MaxActiveSecrets int           // Maximum number of active secrets per client
	RotationPeriod   time.Duration // How often secrets should be rotated
	GracePeriod      time.Duration // How long old secrets remain valid after rotation
	AutoRotate       bool          // Enable automatic rotation
	NotifyBefore     time.Duration // Notify before expiration
}

// DefaultSecretRotationConfig returns default rotation configuration
func DefaultSecretRotationConfig() *SecretRotationConfig {
	return &SecretRotationConfig{
		MaxActiveSecrets: 2,                    // Keep current + 1 previous
		RotationPeriod:   90 * 24 * time.Hour,  // 90 days
		GracePeriod:      7 * 24 * time.Hour,   // 7 days grace period
		AutoRotate:       false,                // Manual rotation by default
		NotifyBefore:     14 * 24 * time.Hour,  // Notify 14 days before expiration
	}
}

// ClientSecretManager handles client secret rotation and validation
type ClientSecretManager struct {
	db     db.DatabaseInterface
	config *SecretRotationConfig
}

// NewClientSecretManager creates a new client secret manager
func NewClientSecretManager(database db.DatabaseInterface, config *SecretRotationConfig) *ClientSecretManager {
	if config == nil {
		config = DefaultSecretRotationConfig()
	}

	return &ClientSecretManager{
		db:     database,
		config: config,
	}
}

// RotateSecret rotates a client's secret
// Returns the new secret in plain text (only time it's available)
func (m *ClientSecretManager) RotateSecret(ctx context.Context, clientID uuid.UUID) (*db.ClientSecret, error) {
	// Generate new secure secret
	plainSecret, err := m.GenerateSecureSecret(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Hash the secret
	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash secret: %w", err)
	}

	// Mark all existing secrets as non-primary
	if err := m.db.MarkSecretsNonPrimary(ctx, clientID); err != nil {
		return nil, fmt.Errorf("failed to mark old secrets as non-primary: %w", err)
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(m.config.RotationPeriod)

	// Create new secret
	secret := &db.ClientSecret{
		ClientID:   clientID,
		SecretHash: string(hash),
		PlainText:  plainSecret, // Only set here, never stored
		IsPrimary:  true,
		CreatedAt:  time.Now(),
		ExpiresAt:  &expiresAt,
		UpdatedAt:  time.Now(),
	}

	if err := m.db.CreateClientSecret(ctx, secret); err != nil {
		return nil, fmt.Errorf("failed to create new secret: %w", err)
	}

	// Cleanup old secrets (keep only MaxActiveSecrets)
	if err := m.db.CleanupOldSecrets(ctx, clientID, m.config.MaxActiveSecrets); err != nil {
		// Log but don't fail - cleanup is non-critical
		log.Printf("Warning: failed to cleanup old secrets for client %s: %v", clientID, err)
	}

	log.Printf("Rotated secret for client %s, new secret expires at %s", clientID, expiresAt.Format(time.RFC3339))

	return secret, nil
}

// ValidateSecret validates a client secret against all active secrets
func (m *ClientSecretManager) ValidateSecret(ctx context.Context, clientID uuid.UUID, providedSecret string) (bool, error) {
	// Get all active (non-expired, non-revoked) secrets
	secrets, err := m.db.GetActiveClientSecrets(ctx, clientID)
	if err != nil {
		return false, fmt.Errorf("failed to get active secrets: %w", err)
	}

	if len(secrets) == 0 {
		log.Printf("No active secrets found for client %s", clientID)
		return false, nil
	}

	// Try each secret
	for _, secret := range secrets {
		err := bcrypt.CompareHashAndPassword([]byte(secret.SecretHash), []byte(providedSecret))
		if err == nil {
			// Valid secret found
			if !secret.IsPrimary {
				log.Printf("Client %s authenticated with non-primary secret (rotation may be in progress)", clientID)
			}

			// Check if secret is within grace period of expiration
			if secret.ExpiresAt != nil && time.Until(*secret.ExpiresAt) < m.config.GracePeriod {
				log.Printf("WARNING: Client %s is using a secret that expires soon: %s",
					clientID, secret.ExpiresAt.Format(time.RFC3339))
			}

			return true, nil
		}
	}

	log.Printf("Failed to validate secret for client %s (tried %d active secrets)", clientID, len(secrets))
	return false, nil
}

// RevokeSecret immediately revokes a specific secret
func (m *ClientSecretManager) RevokeSecret(ctx context.Context, secretID uuid.UUID) error {
	if err := m.db.RevokeClientSecret(ctx, secretID); err != nil {
		return fmt.Errorf("failed to revoke secret: %w", err)
	}

	log.Printf("Revoked secret %s", secretID)
	return nil
}

// GetActiveSecrets returns all active secrets for a client
func (m *ClientSecretManager) GetActiveSecrets(ctx context.Context, clientID uuid.UUID) ([]*db.ClientSecret, error) {
	secrets, err := m.db.GetActiveClientSecrets(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active secrets: %w", err)
	}

	// Never return the hash in the response
	for _, secret := range secrets {
		secret.SecretHash = "" // Clear hash for security
	}

	return secrets, nil
}

// GetExpiringSecrets returns secrets expiring within the configured notice period
func (m *ClientSecretManager) GetExpiringSecrets(ctx context.Context) ([]*db.ClientSecret, error) {
	secrets, err := m.db.GetExpiringSecrets(ctx, m.config.NotifyBefore)
	if err != nil {
		return nil, fmt.Errorf("failed to get expiring secrets: %w", err)
	}

	return secrets, nil
}

// AutoRotateExpiring automatically rotates secrets that are expiring soon
// This would typically be called by a cron job
func (m *ClientSecretManager) AutoRotateExpiring(ctx context.Context) (int, error) {
	if !m.config.AutoRotate {
		return 0, fmt.Errorf("auto-rotation is disabled")
	}

	expiringSecrets, err := m.GetExpiringSecrets(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get expiring secrets: %w", err)
	}

	rotatedCount := 0
	for _, secret := range expiringSecrets {
		// Only rotate primary secrets
		if !secret.IsPrimary {
			continue
		}

		log.Printf("Auto-rotating secret for client %s (expires: %s)",
			secret.ClientID, secret.ExpiresAt.Format(time.RFC3339))

		_, err := m.RotateSecret(ctx, secret.ClientID)
		if err != nil {
			log.Printf("Failed to auto-rotate secret for client %s: %v", secret.ClientID, err)
			continue
		}

		rotatedCount++
	}

	if rotatedCount > 0 {
		log.Printf("Auto-rotated %d secrets", rotatedCount)
	}

	return rotatedCount, nil
}

// GenerateSecureSecret generates a cryptographically secure random secret
func (m *ClientSecretManager) GenerateSecureSecret(length int) (string, error) {
	if length < 16 {
		length = 16 // Minimum secure length
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Base64 URL encoding for use in URLs/headers
	secret := base64.URLEncoding.EncodeToString(bytes)

	// Trim to exact length
	if len(secret) > length {
		secret = secret[:length]
	}

	return secret, nil
}

// GetSecretInfo returns non-sensitive information about a client's secrets
func (m *ClientSecretManager) GetSecretInfo(ctx context.Context, clientID uuid.UUID) (*SecretInfo, error) {
	secrets, err := m.db.GetActiveClientSecrets(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active secrets: %w", err)
	}

	info := &SecretInfo{
		ClientID:      clientID,
		ActiveCount:   len(secrets),
		Secrets:       make([]SecretDetail, 0, len(secrets)),
	}

	for _, secret := range secrets {
		detail := SecretDetail{
			ID:        secret.ID,
			CreatedAt: secret.CreatedAt,
			ExpiresAt: secret.ExpiresAt,
			IsPrimary: secret.IsPrimary,
			RevokedAt: secret.RevokedAt,
		}

		if secret.ExpiresAt != nil {
			timeUntilExpiry := time.Until(*secret.ExpiresAt)
			detail.DaysUntilExpiry = int(timeUntilExpiry.Hours() / 24)
			detail.IsExpiringSoon = timeUntilExpiry < m.config.NotifyBefore
		}

		info.Secrets = append(info.Secrets, detail)

		if secret.IsPrimary {
			info.PrimarySecretID = &secret.ID
			if secret.ExpiresAt != nil {
				info.PrimaryExpiresAt = secret.ExpiresAt
			}
		}
	}

	return info, nil
}

// SecretInfo contains non-sensitive information about a client's secrets
type SecretInfo struct {
	ClientID         uuid.UUID      `json:"client_id"`
	ActiveCount      int            `json:"active_count"`
	PrimarySecretID  *uuid.UUID     `json:"primary_secret_id,omitempty"`
	PrimaryExpiresAt *time.Time     `json:"primary_expires_at,omitempty"`
	Secrets          []SecretDetail `json:"secrets"`
}

// SecretDetail contains details about a specific secret
type SecretDetail struct {
	ID              uuid.UUID  `json:"id"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	IsPrimary       bool       `json:"is_primary"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	DaysUntilExpiry int        `json:"days_until_expiry,omitempty"`
	IsExpiringSoon  bool       `json:"is_expiring_soon"`
}
