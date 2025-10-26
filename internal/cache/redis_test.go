package cache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"oauth-server/internal/db"
)

// MockRedisClient is a mock implementation of Redis client for testing
type MockRedisClient struct {
	data   map[string][]byte
	ttls   map[string]time.Time
	errors map[string]error
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data:   make(map[string][]byte),
		ttls:   make(map[string]time.Time),
		errors: make(map[string]error),
	}
}

func (m *MockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)

	// Check if error is set for this key
	if err, ok := m.errors[key]; ok {
		cmd.SetErr(err)
		return cmd
	}

	// Check if key exists
	data, ok := m.data[key]
	if !ok {
		cmd.SetErr(redis.Nil)
		return cmd
	}

	// Check if TTL has expired
	if ttl, hasTTL := m.ttls[key]; hasTTL && time.Now().After(ttl) {
		delete(m.data, key)
		delete(m.ttls, key)
		cmd.SetErr(redis.Nil)
		return cmd
	}

	cmd.SetVal(string(data))
	return cmd
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)

	// Check if error is set for this key
	if err, ok := m.errors[key]; ok {
		cmd.SetErr(err)
		return cmd
	}

	// Store the value
	if strVal, ok := value.(string); ok {
		m.data[key] = []byte(strVal)
	} else if byteVal, ok := value.([]byte); ok {
		m.data[key] = byteVal
	}

	// Set TTL if provided
	if ttl > 0 {
		m.ttls[key] = time.Now().Add(ttl)
	}

	cmd.SetVal("OK")
	return cmd
}

func (m *MockRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)

	deleted := int64(0)
	for _, key := range keys {
		if _, ok := m.data[key]; ok {
			delete(m.data, key)
			delete(m.ttls, key)
			deleted++
		}
	}

	cmd.SetVal(deleted)
	return cmd
}

func (m *MockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("PONG")
	return cmd
}

func (m *MockRedisClient) Close() error {
	return nil
}

func (m *MockRedisClient) SetError(key string, err error) {
	m.errors[key] = err
}

// Test token caching operations
func TestTokenCaching(t *testing.T) {
	mockClient := NewMockRedisClient()
	cache := &RedisCache{
		client: &mockRedisAdapter{mock: mockClient},
	}

	ctx := context.Background()
	tokenHash := "abc123"

	t.Run("cache miss returns ErrCacheMiss", func(t *testing.T) {
		_, err := cache.GetToken(ctx, tokenHash)
		if err != ErrCacheMiss {
			t.Errorf("Expected ErrCacheMiss, got %v", err)
		}

		stats := cache.GetStats()
		if stats.Misses != 1 {
			t.Errorf("Expected 1 miss, got %d", stats.Misses)
		}
	})

	t.Run("set and get token", func(t *testing.T) {
		token := &db.AccessToken{
			ID:        uuid.New(),
			Token:     "test-token",
			ClientID:  "client-1",
			UserID:    uuid.New(),
			Scopes:    []string{"read", "write"},
			ExpiresAt: time.Now().Add(time.Hour),
		}

		// Set token
		err := cache.SetToken(ctx, tokenHash, token, 5*time.Minute)
		if err != nil {
			t.Fatalf("Failed to set token: %v", err)
		}

		// Get token
		cached, err := cache.GetToken(ctx, tokenHash)
		if err != nil {
			t.Fatalf("Failed to get token: %v", err)
		}

		if cached.Token != token.Token {
			t.Errorf("Expected token %s, got %s", token.Token, cached.Token)
		}

		stats := cache.GetStats()
		if stats.Hits != 1 {
			t.Errorf("Expected 1 hit, got %d", stats.Hits)
		}
	})

	t.Run("invalidate token", func(t *testing.T) {
		// First set a token
		token := &db.AccessToken{
			ID:        uuid.New(),
			Token:     "test-token-2",
			ClientID:  "client-1",
			UserID:    uuid.New(),
			Scopes:    []string{"read"},
			ExpiresAt: time.Now().Add(time.Hour),
		}

		tokenHash2 := "def456"
		err := cache.SetToken(ctx, tokenHash2, token, 5*time.Minute)
		if err != nil {
			t.Fatalf("Failed to set token: %v", err)
		}

		// Invalidate it
		err = cache.InvalidateToken(ctx, tokenHash2)
		if err != nil {
			t.Fatalf("Failed to invalidate token: %v", err)
		}

		// Try to get it - should be cache miss
		_, err = cache.GetToken(ctx, tokenHash2)
		if err != ErrCacheMiss {
			t.Errorf("Expected ErrCacheMiss after invalidation, got %v", err)
		}
	})

	t.Run("revoked token is cached", func(t *testing.T) {
		now := time.Now()
		revokedToken := &db.AccessToken{
			ID:         uuid.New(),
			Token:      "revoked-token",
			ClientID:   "client-1",
			UserID:     uuid.New(),
			Scopes:     []string{"read"},
			ExpiresAt:  time.Now().Add(time.Hour),
			RevokedAt:  &now,
		}

		tokenHash3 := "ghi789"
		err := cache.SetToken(ctx, tokenHash3, revokedToken, 5*time.Minute)
		if err != nil {
			t.Fatalf("Failed to set revoked token: %v", err)
		}

		// Get it back
		cached, err := cache.GetToken(ctx, tokenHash3)
		if err != nil {
			t.Fatalf("Failed to get revoked token: %v", err)
		}

		if cached.RevokedAt == nil {
			t.Error("Expected RevokedAt to be set")
		}
	})
}

// Test user caching operations
func TestUserCaching(t *testing.T) {
	mockClient := NewMockRedisClient()
	cache := &RedisCache{
		client: &mockRedisAdapter{mock: mockClient},
	}

	ctx := context.Background()
	userID := uuid.New().String()

	t.Run("cache miss for user", func(t *testing.T) {
		_, err := cache.GetUser(ctx, userID)
		if err != ErrCacheMiss {
			t.Errorf("Expected ErrCacheMiss, got %v", err)
		}
	})

	t.Run("set and get user", func(t *testing.T) {
		user := &db.User{
			ID:       uuid.New(),
			Username: "testuser",
			Email:    "test@example.com",
			Password: "hashed-password",
		}

		err := cache.SetUser(ctx, userID, user, 15*time.Minute)
		if err != nil {
			t.Fatalf("Failed to set user: %v", err)
		}

		cached, err := cache.GetUser(ctx, userID)
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		if cached.Username != user.Username {
			t.Errorf("Expected username %s, got %s", user.Username, cached.Username)
		}
	})

	t.Run("invalidate user", func(t *testing.T) {
		err := cache.InvalidateUser(ctx, userID)
		if err != nil {
			t.Fatalf("Failed to invalidate user: %v", err)
		}

		_, err = cache.GetUser(ctx, userID)
		if err != ErrCacheMiss {
			t.Errorf("Expected ErrCacheMiss after invalidation, got %v", err)
		}
	})
}

// Test client caching operations
func TestClientCaching(t *testing.T) {
	mockClient := NewMockRedisClient()
	cache := &RedisCache{
		client: &mockRedisAdapter{mock: mockClient},
	}

	ctx := context.Background()
	clientID := "client-123"

	t.Run("set and get client", func(t *testing.T) {
		client := &db.Client{
			ID:           uuid.New(),
			ClientID:     clientID,
			ClientSecret: "secret",
			Name:         "Test Client",
			RedirectURIs: []string{"http://localhost:3000/callback"},
			GrantTypes:   []string{"authorization_code"},
			Scopes:       []string{"read", "write"},
			IsPublic:     false,
		}

		err := cache.SetClient(ctx, clientID, client, 30*time.Minute)
		if err != nil {
			t.Fatalf("Failed to set client: %v", err)
		}

		cached, err := cache.GetClient(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to get client: %v", err)
		}

		if cached.ClientID != client.ClientID {
			t.Errorf("Expected client ID %s, got %s", client.ClientID, cached.ClientID)
		}
	})
}

// Test cache statistics
func TestCacheStats(t *testing.T) {
	mockClient := NewMockRedisClient()
	cache := &RedisCache{
		client: &mockRedisAdapter{mock: mockClient},
	}

	ctx := context.Background()

	// Generate some cache activity
	_, _ = cache.GetToken(ctx, "miss1") // miss
	_, _ = cache.GetToken(ctx, "miss2") // miss

	token := &db.AccessToken{
		ID:        uuid.New(),
		Token:     "test",
		ClientID:  "client",
		UserID:    uuid.New(),
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
	}

	_ = cache.SetToken(ctx, "hit1", token, 5*time.Minute)
	_, _ = cache.GetToken(ctx, "hit1") // hit

	stats := cache.GetStats()

	if stats.Hits != 1 {
		t.Errorf("Expected 1 hit, got %d", stats.Hits)
	}

	if stats.Misses != 2 {
		t.Errorf("Expected 2 misses, got %d", stats.Misses)
	}

	// Reset stats
	cache.ResetStats()
	stats = cache.GetStats()

	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("Stats not reset properly")
	}
}

// Test cache health check
func TestCacheHealthCheck(t *testing.T) {
	mockClient := NewMockRedisClient()
	cache := &RedisCache{
		client: &mockRedisAdapter{mock: mockClient},
	}

	ctx := context.Background()

	err := cache.Ping(ctx)
	if err != nil {
		t.Errorf("Ping failed: %v", err)
	}
}

// Test error handling
func TestCacheErrorHandling(t *testing.T) {
	mockClient := NewMockRedisClient()
	cache := &RedisCache{
		client: &mockRedisAdapter{mock: mockClient},
	}

	ctx := context.Background()

	t.Run("invalid JSON in cache", func(t *testing.T) {
		// Manually insert invalid JSON
		tokenHash := "invalid-json"
		mockClient.data["token:"+tokenHash] = []byte("not valid json")

		_, err := cache.GetToken(ctx, tokenHash)
		if err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}

		stats := cache.GetStats()
		if stats.Errors == 0 {
			t.Error("Expected error count to increment")
		}
	})
}

// mockRedisAdapter adapts our mock to the redis.Client interface
type mockRedisAdapter struct {
	mock *MockRedisClient
}

func (a *mockRedisAdapter) Get(ctx context.Context, key string) *redis.StringCmd {
	return a.mock.Get(ctx, key)
}

func (a *mockRedisAdapter) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	return a.mock.Set(ctx, key, value, ttl)
}

func (a *mockRedisAdapter) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	return a.mock.Del(ctx, keys...)
}

func (a *mockRedisAdapter) Ping(ctx context.Context) *redis.StatusCmd {
	return a.mock.Ping(ctx)
}

func (a *mockRedisAdapter) Close() error {
	return a.mock.Close()
}
