package logging

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
)

var requestCounter uint64

// GenerateRequestID generates a unique request ID
// Format: req-{counter}-{random}
func GenerateRequestID() string {
	// Increment counter atomically
	count := atomic.AddUint64(&requestCounter, 1)

	// Generate 8 random bytes
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to counter-only if random fails
		return fmt.Sprintf("req-%d", count)
	}

	// Combine counter and random hex
	return fmt.Sprintf("req-%d-%s", count, hex.EncodeToString(randomBytes))
}
