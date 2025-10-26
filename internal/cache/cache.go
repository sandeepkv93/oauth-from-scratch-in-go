package cache

import (
	"context"
	"time"

	"oauth-server/internal/db"
)

// Cache defines the interface for caching operations
type Cache interface {
	// Token operations
	GetToken(ctx context.Context, tokenHash string) (*db.AccessToken, error)
	SetToken(ctx context.Context, tokenHash string, token *db.AccessToken, ttl time.Duration) error
	InvalidateToken(ctx context.Context, tokenHash string) error

	// User operations
	GetUser(ctx context.Context, userID string) (*db.User, error)
	SetUser(ctx context.Context, userID string, user *db.User, ttl time.Duration) error
	InvalidateUser(ctx context.Context, userID string) error

	// Client operations
	GetClient(ctx context.Context, clientID string) (*db.Client, error)
	SetClient(ctx context.Context, clientID string, client *db.Client, ttl time.Duration) error
	InvalidateClient(ctx context.Context, clientID string) error

	// Utility operations
	Ping(ctx context.Context) error
	Close() error
	GetStats() CacheStats
}

// CacheStats holds cache performance metrics
type CacheStats struct {
	Hits   int64
	Misses int64
	Errors int64
}

// ErrCacheMiss is returned when a key is not found in the cache
var ErrCacheMiss = &CacheError{Message: "cache miss"}

// CacheError represents a cache-specific error
type CacheError struct {
	Message string
	Err     error
}

func (e *CacheError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *CacheError) Unwrap() error {
	return e.Err
}

// IsCacheMiss returns true if the error is a cache miss
func IsCacheMiss(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*CacheError)
	return ok && err.Error() == "cache miss"
}
