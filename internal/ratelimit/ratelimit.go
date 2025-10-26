package ratelimit

import (
	"time"
)

// RateLimitResult contains the result of a rate limit check
type RateLimitResult struct {
	Allowed   bool
	Limit     int
	Remaining int
	ResetTime time.Time
}

// RateLimiter is the interface for rate limiting implementations
type RateLimiter interface {
	// Allow checks if a request should be allowed
	// Returns result with limit information
	Allow(key string) (*RateLimitResult, error)

	// Close cleans up resources
	Close() error
}

// Config holds rate limiter configuration
type Config struct {
	MaxRequests int
	Window      time.Duration
}
