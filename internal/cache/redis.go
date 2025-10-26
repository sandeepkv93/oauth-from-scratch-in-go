package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"oauth-server/internal/db"
)

// RedisClient defines the interface for Redis operations needed by the cache
type RedisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
}

// RedisCache implements the Cache interface using Redis
type RedisCache struct {
	client RedisClient
	hits   int64
	misses int64
	errors int64
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(client RedisClient) *RedisCache {
	return &RedisCache{
		client: client,
	}
}

// GetToken retrieves an access token from cache
func (c *RedisCache) GetToken(ctx context.Context, tokenHash string) (*db.AccessToken, error) {
	key := fmt.Sprintf("token:%s", tokenHash)

	data, err := c.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		atomic.AddInt64(&c.misses, 1)
		return nil, ErrCacheMiss
	}
	if err != nil {
		atomic.AddInt64(&c.errors, 1)
		return nil, &CacheError{Message: "failed to get token from cache", Err: err}
	}

	var token db.AccessToken
	if err := json.Unmarshal(data, &token); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return nil, &CacheError{Message: "failed to unmarshal token", Err: err}
	}

	atomic.AddInt64(&c.hits, 1)
	return &token, nil
}

// SetToken stores an access token in cache
func (c *RedisCache) SetToken(ctx context.Context, tokenHash string, token *db.AccessToken, ttl time.Duration) error {
	key := fmt.Sprintf("token:%s", tokenHash)

	data, err := json.Marshal(token)
	if err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to marshal token", Err: err}
	}

	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to set token in cache", Err: err}
	}

	return nil
}

// InvalidateToken removes an access token from cache
func (c *RedisCache) InvalidateToken(ctx context.Context, tokenHash string) error {
	key := fmt.Sprintf("token:%s", tokenHash)

	if err := c.client.Del(ctx, key).Err(); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to invalidate token", Err: err}
	}

	return nil
}

// GetUser retrieves a user from cache
func (c *RedisCache) GetUser(ctx context.Context, userID string) (*db.User, error) {
	key := fmt.Sprintf("user:%s", userID)

	data, err := c.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		atomic.AddInt64(&c.misses, 1)
		return nil, ErrCacheMiss
	}
	if err != nil {
		atomic.AddInt64(&c.errors, 1)
		return nil, &CacheError{Message: "failed to get user from cache", Err: err}
	}

	var user db.User
	if err := json.Unmarshal(data, &user); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return nil, &CacheError{Message: "failed to unmarshal user", Err: err}
	}

	atomic.AddInt64(&c.hits, 1)
	return &user, nil
}

// SetUser stores a user in cache
func (c *RedisCache) SetUser(ctx context.Context, userID string, user *db.User, ttl time.Duration) error {
	key := fmt.Sprintf("user:%s", userID)

	data, err := json.Marshal(user)
	if err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to marshal user", Err: err}
	}

	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to set user in cache", Err: err}
	}

	return nil
}

// InvalidateUser removes a user from cache
func (c *RedisCache) InvalidateUser(ctx context.Context, userID string) error {
	key := fmt.Sprintf("user:%s", userID)

	if err := c.client.Del(ctx, key).Err(); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to invalidate user", Err: err}
	}

	return nil
}

// GetClient retrieves a client from cache
func (c *RedisCache) GetClient(ctx context.Context, clientID string) (*db.Client, error) {
	key := fmt.Sprintf("client:%s", clientID)

	data, err := c.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		atomic.AddInt64(&c.misses, 1)
		return nil, ErrCacheMiss
	}
	if err != nil {
		atomic.AddInt64(&c.errors, 1)
		return nil, &CacheError{Message: "failed to get client from cache", Err: err}
	}

	var client db.Client
	if err := json.Unmarshal(data, &client); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return nil, &CacheError{Message: "failed to unmarshal client", Err: err}
	}

	atomic.AddInt64(&c.hits, 1)
	return &client, nil
}

// SetClient stores a client in cache
func (c *RedisCache) SetClient(ctx context.Context, clientID string, client *db.Client, ttl time.Duration) error {
	key := fmt.Sprintf("client:%s", clientID)

	data, err := json.Marshal(client)
	if err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to marshal client", Err: err}
	}

	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to set client in cache", Err: err}
	}

	return nil
}

// InvalidateClient removes a client from cache
func (c *RedisCache) InvalidateClient(ctx context.Context, clientID string) error {
	key := fmt.Sprintf("client:%s", clientID)

	if err := c.client.Del(ctx, key).Err(); err != nil {
		atomic.AddInt64(&c.errors, 1)
		return &CacheError{Message: "failed to invalidate client", Err: err}
	}

	return nil
}

// Ping checks if Redis is reachable
func (c *RedisCache) Ping(ctx context.Context) error {
	if err := c.client.Ping(ctx).Err(); err != nil {
		return &CacheError{Message: "redis ping failed", Err: err}
	}
	return nil
}

// Close closes the Redis client connection
func (c *RedisCache) Close() error {
	return c.client.Close()
}

// GetStats returns cache performance statistics
func (c *RedisCache) GetStats() CacheStats {
	return CacheStats{
		Hits:   atomic.LoadInt64(&c.hits),
		Misses: atomic.LoadInt64(&c.misses),
		Errors: atomic.LoadInt64(&c.errors),
	}
}

// ResetStats resets cache performance statistics
func (c *RedisCache) ResetStats() {
	atomic.StoreInt64(&c.hits, 0)
	atomic.StoreInt64(&c.misses, 0)
	atomic.StoreInt64(&c.errors, 0)
}
