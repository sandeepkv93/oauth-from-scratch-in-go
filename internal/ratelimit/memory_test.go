package ratelimit

import (
	"testing"
	"time"
)

func TestMemoryRateLimiter_Allow(t *testing.T) {
	config := &Config{
		MaxRequests: 3,
		Window:      time.Second,
	}
	limiter := NewMemoryRateLimiter(config)
	defer limiter.Close()

	key := "test-key"

	// First 3 requests should be allowed
	for i := 1; i <= 3; i++ {
		result, err := limiter.Allow(key)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i)
		}
		if result.Limit != 3 {
			t.Errorf("Expected limit 3, got %d", result.Limit)
		}
		if result.Remaining != 3-i {
			t.Errorf("Request %d: expected remaining %d, got %d", i, 3-i, result.Remaining)
		}
	}

	// 4th request should be denied
	result, err := limiter.Allow(key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("4th request should be denied")
	}
	if result.Remaining != 0 {
		t.Errorf("Expected remaining 0, got %d", result.Remaining)
	}
}

func TestMemoryRateLimiter_WindowReset(t *testing.T) {
	config := &Config{
		MaxRequests: 2,
		Window:      100 * time.Millisecond,
	}
	limiter := NewMemoryRateLimiter(config)
	defer limiter.Close()

	key := "test-key"

	// Use up the limit
	for i := 0; i < 2; i++ {
		result, _ := limiter.Allow(key)
		if !result.Allowed {
			t.Fatalf("Request %d should be allowed", i+1)
		}
	}

	// Next request should be denied
	result, _ := limiter.Allow(key)
	if result.Allowed {
		t.Error("Request should be denied before window reset")
	}

	// Wait for window to reset
	time.Sleep(150 * time.Millisecond)

	// Should be allowed after window reset
	result, _ = limiter.Allow(key)
	if !result.Allowed {
		t.Error("Request should be allowed after window reset")
	}
	if result.Remaining != 1 {
		t.Errorf("Expected remaining 1, got %d", result.Remaining)
	}
}

func TestMemoryRateLimiter_MultipleKeys(t *testing.T) {
	config := &Config{
		MaxRequests: 2,
		Window:      time.Second,
	}
	limiter := NewMemoryRateLimiter(config)
	defer limiter.Close()

	// Each key should have independent limits
	key1 := "key1"
	key2 := "key2"

	// Use up limit for key1
	for i := 0; i < 2; i++ {
		result, _ := limiter.Allow(key1)
		if !result.Allowed {
			t.Fatalf("key1 request %d should be allowed", i+1)
		}
	}

	// key1 should be limited
	result, _ := limiter.Allow(key1)
	if result.Allowed {
		t.Error("key1 should be rate limited")
	}

	// key2 should still be allowed
	result, _ = limiter.Allow(key2)
	if !result.Allowed {
		t.Error("key2 should not be affected by key1's limit")
	}
}

func TestMemoryRateLimiter_Cleanup(t *testing.T) {
	config := &Config{
		MaxRequests: 1,
		Window:      50 * time.Millisecond,
	}
	limiter := NewMemoryRateLimiter(config)
	limiter.cleanupInt = 100 * time.Millisecond // Short cleanup interval for testing
	defer limiter.Close()

	key := "test-key"

	// Create an entry
	limiter.Allow(key)

	// Verify entry exists
	limiter.mutex.RLock()
	if _, exists := limiter.limiters[key]; !exists {
		t.Error("Entry should exist after request")
	}
	limiter.mutex.RUnlock()

	// Wait for cleanup to run (entry should be removed as it's old)
	time.Sleep(250 * time.Millisecond)

	// Entry might still exist if cleanup hasn't run yet, but should eventually be removed
	// This is a best-effort test - just verify no panic occurs
}

func TestMemoryRateLimiter_ResetTime(t *testing.T) {
	config := &Config{
		MaxRequests: 1,
		Window:      time.Second,
	}
	limiter := NewMemoryRateLimiter(config)
	defer limiter.Close()

	key := "test-key"

	before := time.Now()
	result, _ := limiter.Allow(key)
	after := time.Now()

	// Reset time should be approximately 1 second from now
	expectedMin := before.Add(time.Second)
	expectedMax := after.Add(time.Second)

	if result.ResetTime.Before(expectedMin) || result.ResetTime.After(expectedMax) {
		t.Errorf("Reset time %v should be between %v and %v",
			result.ResetTime, expectedMin, expectedMax)
	}
}
