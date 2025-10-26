package ratelimit

import (
	"sync"
	"time"
)

// MemoryRateLimiter implements in-memory rate limiting
type MemoryRateLimiter struct {
	config     *Config
	limiters   map[string]*limiterEntry
	mutex      sync.RWMutex
	cleanupInt time.Duration
	stopClean  chan struct{}
}

type limiterEntry struct {
	requests int
	window   time.Time
}

// NewMemoryRateLimiter creates a new in-memory rate limiter
func NewMemoryRateLimiter(config *Config) *MemoryRateLimiter {
	m := &MemoryRateLimiter{
		config:     config,
		limiters:   make(map[string]*limiterEntry),
		cleanupInt: 5 * time.Minute, // Cleanup stale entries every 5 minutes
		stopClean:  make(chan struct{}),
	}

	// Start background cleanup
	go m.cleanup()

	return m
}

// Allow checks if a request should be allowed
func (m *MemoryRateLimiter) Allow(key string) (*RateLimitResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()
	entry, exists := m.limiters[key]

	if !exists {
		entry = &limiterEntry{
			requests: 0,
			window:   now,
		}
		m.limiters[key] = entry
	}

	// Reset window if expired
	if now.Sub(entry.window) > m.config.Window {
		entry.requests = 0
		entry.window = now
	}

	// Check if limit exceeded
	if entry.requests >= m.config.MaxRequests {
		return &RateLimitResult{
			Allowed:   false,
			Limit:     m.config.MaxRequests,
			Remaining: 0,
			ResetTime: entry.window.Add(m.config.Window),
		}, nil
	}

	// Increment counter
	entry.requests++

	return &RateLimitResult{
		Allowed:   true,
		Limit:     m.config.MaxRequests,
		Remaining: m.config.MaxRequests - entry.requests,
		ResetTime: entry.window.Add(m.config.Window),
	}, nil
}

// cleanup removes stale entries periodically
func (m *MemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(m.cleanupInt)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mutex.Lock()
			now := time.Now()
			for key, entry := range m.limiters {
				// Remove entries older than 2x window duration
				if now.Sub(entry.window) > 2*m.config.Window {
					delete(m.limiters, key)
				}
			}
			m.mutex.Unlock()
		case <-m.stopClean:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (m *MemoryRateLimiter) Close() error {
	close(m.stopClean)
	return nil
}
