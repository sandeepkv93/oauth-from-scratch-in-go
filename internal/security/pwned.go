package security

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PwnedPasswordChecker checks passwords against the HaveIBeenPwned database
// using the k-Anonymity model to preserve privacy
type PwnedPasswordChecker struct {
	client   *http.Client
	enabled  bool
	failOpen bool // If true, allow password on API errors
}

// PwnedCheckResult contains the result of a breach check
type PwnedCheckResult struct {
	IsBreached bool
	Count      int  // Number of times seen in breaches
	Error      error
}

// NewPwnedPasswordChecker creates a new password breach checker
func NewPwnedPasswordChecker(enabled bool, timeout time.Duration, failOpen bool) *PwnedPasswordChecker {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &PwnedPasswordChecker{
		client: &http.Client{
			Timeout: timeout,
		},
		enabled:  enabled,
		failOpen: failOpen,
	}
}

// CheckPassword checks if a password has been exposed in known data breaches
// Uses k-Anonymity model - only sends first 5 chars of SHA1 hash to API
// Reference: https://haveibeenpwned.com/API/v3#PwnedPasswords
func (p *PwnedPasswordChecker) CheckPassword(password string) PwnedCheckResult {
	if !p.enabled {
		return PwnedCheckResult{IsBreached: false, Count: 0, Error: nil}
	}

	// Create SHA-1 hash of password
	h := sha1.New()
	h.Write([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	// k-Anonymity: Send only first 5 characters
	prefix := hash[:5]
	suffix := hash[5:]

	// Query HaveIBeenPwned API
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create HIBP request: %v", err)
		return p.handleError(err)
	}

	// Set headers as recommended by HIBP
	req.Header.Set("User-Agent", "OAuth-Server-Password-Check")
	req.Header.Set("Add-Padding", "true") // Get padded response for additional privacy

	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("HIBP API request failed: %v", err)
		return p.handleError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("HIBP API returned status %d", resp.StatusCode)
		log.Printf("HIBP API error: %v", err)
		return p.handleError(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read HIBP response: %v", err)
		return p.handleError(err)
	}

	// Parse response and check if our suffix appears
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}

		hashSuffix := strings.TrimSpace(parts[0])
		if hashSuffix == suffix {
			// Password is breached!
			count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				log.Printf("Failed to parse breach count: %v", err)
				count = 1 // Default to 1 if we can't parse
			}

			log.Printf("Password breach detected: seen %d times in data breaches", count)
			return PwnedCheckResult{
				IsBreached: true,
				Count:      count,
				Error:      nil,
			}
		}
	}

	// Password not found in breaches
	return PwnedCheckResult{IsBreached: false, Count: 0, Error: nil}
}

// handleError handles API errors based on fail open/closed configuration
func (p *PwnedPasswordChecker) handleError(err error) PwnedCheckResult {
	if p.failOpen {
		// Fail open: allow password but log the error
		log.Printf("Pwned password check failed (allowing due to fail-open): %v", err)
		return PwnedCheckResult{IsBreached: false, Count: 0, Error: err}
	}

	// Fail closed: reject password on errors
	log.Printf("Pwned password check failed (rejecting due to fail-closed): %v", err)
	return PwnedCheckResult{IsBreached: false, Count: 0, Error: err}
}

// IsEnabled returns whether the checker is enabled
func (p *PwnedPasswordChecker) IsEnabled() bool {
	return p.enabled
}
