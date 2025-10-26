package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements distributed rate limiting using Redis
// Uses sliding window algorithm with sorted sets
type RedisRateLimiter struct {
	client *redis.Client
	config *Config
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(client *redis.Client, config *Config) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		config: config,
	}
}

// Allow checks if a request should be allowed using sliding window algorithm
func (r *RedisRateLimiter) Allow(key string) (*RateLimitResult, error) {
	ctx := context.Background()
	now := time.Now()
	windowStart := now.Add(-r.config.Window)

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Redis key for this rate limit
	redisKey := fmt.Sprintf("ratelimit:%s", key)

	// 1. Remove old entries outside the sliding window
	pipe.ZRemRangeByScore(ctx, redisKey, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// 2. Count current requests in window
	countCmd := pipe.ZCard(ctx, redisKey)

	// 3. Add current request with timestamp as score and member
	// Using nanosecond precision for uniqueness
	requestID := fmt.Sprintf("%d", now.UnixNano())
	pipe.ZAdd(ctx, redisKey, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: requestID,
	})

	// 4. Set expiration on the key (2x window for cleanup)
	pipe.Expire(ctx, redisKey, r.config.Window*2)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis pipeline failed: %w", err)
	}

	// Get the count before we added the new request
	count := int(countCmd.Val())

	// Calculate reset time (end of current window)
	resetTime := now.Add(r.config.Window)

	// Check if limit exceeded (count was before increment)
	if count >= r.config.MaxRequests {
		return &RateLimitResult{
			Allowed:   false,
			Limit:     r.config.MaxRequests,
			Remaining: 0,
			ResetTime: resetTime,
		}, nil
	}

	return &RateLimitResult{
		Allowed:   true,
		Limit:     r.config.MaxRequests,
		Remaining: r.config.MaxRequests - count - 1, // -1 for the request we just added
		ResetTime: resetTime,
	}, nil
}

// Close closes the Redis connection
func (r *RedisRateLimiter) Close() error {
	return r.client.Close()
}
