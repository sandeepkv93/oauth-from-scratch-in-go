package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken   = errors.New("invalid CSRF token")
	ErrExpiredToken   = errors.New("CSRF token expired")
	ErrMalformedToken = errors.New("malformed CSRF token")
)

// CSRFManager manages CSRF token generation and validation
type CSRFManager struct {
	secret []byte
	ttl    time.Duration
	mu     sync.RWMutex
}

// NewCSRFManager creates a new CSRF manager
func NewCSRFManager(secret string, ttl time.Duration) *CSRFManager {
	if ttl == 0 {
		ttl = 24 * time.Hour // Default 24 hours
	}

	return &CSRFManager{
		secret: []byte(secret),
		ttl:    ttl,
	}
}

// GenerateToken generates a new CSRF token
// Format: base64(timestamp:random:signature)
func (m *CSRFManager) GenerateToken(sessionID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	timestamp := time.Now().Unix()

	// Generate random bytes
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	randomStr := base64.URLEncoding.EncodeToString(randomBytes)

	// Create message to sign
	message := fmt.Sprintf("%d:%s:%s", timestamp, sessionID, randomStr)

	// Generate HMAC signature
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	// Combine everything
	token := fmt.Sprintf("%s:%s", message, base64.URLEncoding.EncodeToString(signature))

	// Base64 encode the entire token
	return base64.URLEncoding.EncodeToString([]byte(token)), nil
}

// ValidateToken validates a CSRF token
func (m *CSRFManager) ValidateToken(token string, sessionID string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Decode base64
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return ErrMalformedToken
	}

	// Split into parts
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 4 {
		return ErrMalformedToken
	}

	timestampStr := parts[0]
	providedSessionID := parts[1]
	randomStr := parts[2]
	providedSignature := parts[3]

	// Validate session ID matches
	if providedSessionID != sessionID {
		return ErrInvalidToken
	}

	// Parse timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return ErrMalformedToken
	}

	// Check if token is expired
	tokenTime := time.Unix(timestamp, 0)
	if time.Since(tokenTime) > m.ttl {
		return ErrExpiredToken
	}

	// Reconstruct message
	message := fmt.Sprintf("%s:%s:%s", timestampStr, providedSessionID, randomStr)

	// Verify signature
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(message))
	expectedSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	// Constant-time comparison
	if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
		return ErrInvalidToken
	}

	return nil
}
