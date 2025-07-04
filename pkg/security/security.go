package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type SecurityValidator struct {
	trustedProxies []string
	maxLoginAttempts int
	lockoutDuration time.Duration
}

func NewSecurityValidator() *SecurityValidator {
	return &SecurityValidator{
		trustedProxies: []string{"127.0.0.1", "::1"},
		maxLoginAttempts: 5,
		lockoutDuration: 15 * time.Minute,
	}
}

func (sv *SecurityValidator) ValidateRedirectURI(redirectURI string, allowedURIs []string) error {
	if redirectURI == "" {
		return errors.New("redirect URI is required")
	}
	
	for _, allowed := range allowedURIs {
		if redirectURI == allowed {
			return nil
		}
	}
	
	return errors.New("redirect URI not allowed")
}

func (sv *SecurityValidator) IsValidScope(scope string) bool {
	validScopes := []string{"read", "write", "admin", "openid", "profile", "email"}
	
	for _, validScope := range validScopes {
		if scope == validScope {
			return true
		}
	}
	
	return false
}

func (sv *SecurityValidator) GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (sv *SecurityValidator) ValidateClientIP(clientIP string, allowedIPs []string) bool {
	if len(allowedIPs) == 0 {
		return true
	}
	
	for _, allowed := range allowedIPs {
		if clientIP == allowed {
			return true
		}
		
		if _, network, err := net.ParseCIDR(allowed); err == nil {
			if ip := net.ParseIP(clientIP); ip != nil {
				if network.Contains(ip) {
					return true
				}
			}
		}
	}
	
	return false
}

func (sv *SecurityValidator) SanitizeInput(input string) string {
	input = strings.ReplaceAll(input, "\n", "")
	input = strings.ReplaceAll(input, "\r", "")
	input = strings.ReplaceAll(input, "\t", "")
	
	if len(input) > 1000 {
		input = input[:1000]
	}
	
	return input
}

func (sv *SecurityValidator) IsPasswordBreached(password string) bool {
	commonPasswords := []string{
		"password", "123456", "123456789", "qwerty", "abc123",
		"password123", "admin", "letmein", "welcome", "monkey",
	}
	
	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if lowerPassword == common {
			return true
		}
	}
	
	return false
}

func (sv *SecurityValidator) ValidateUserAgent(userAgent string) error {
	if len(userAgent) == 0 {
		return errors.New("user agent is required")
	}
	
	if len(userAgent) > 500 {
		return errors.New("user agent too long")
	}
	
	suspiciousPatterns := []string{
		"<script", "javascript:", "vbscript:", "onload=", "onerror=",
	}
	
	lowerUA := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerUA, pattern) {
			return fmt.Errorf("suspicious user agent detected: %s", pattern)
		}
	}
	
	return nil
}

func (sv *SecurityValidator) SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (sv *SecurityValidator) ValidateJSONInput(input []byte) error {
	if len(input) > 10*1024*1024 {
		return errors.New("JSON payload too large")
	}
	
	inputStr := string(input)
	if strings.Contains(inputStr, "<?xml") {
		return errors.New("XML not allowed in JSON input")
	}
	
	return nil
}

func (sv *SecurityValidator) IsSecureTransport(isHTTPS bool, forwardedProto string) bool {
	return isHTTPS || forwardedProto == "https"
}

func (sv *SecurityValidator) ValidateCSRFToken(provided, expected string) bool {
	if len(provided) == 0 || len(expected) == 0 {
		return false
	}
	
	return sv.SecureCompare(provided, expected)
}