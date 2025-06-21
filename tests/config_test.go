package tests

import (
	"os"
	"testing"
	"time"

	"oauth-server/internal/config"
)

func TestConfigLoad(t *testing.T) {
	cfg := config.Load()

	if cfg == nil {
		t.Fatal("Config should not be nil")
	}

	if cfg.Server.Host == "" {
		t.Error("Server host should not be empty")
	}

	if cfg.Server.Port == "" {
		t.Error("Server port should not be empty")
	}

	if cfg.Database.Host == "" {
		t.Error("Database host should not be empty")
	}

	if cfg.Auth.JWTSecret == "" {
		t.Error("JWT secret should not be empty")
	}
}

func TestConfigEnvironmentVariables(t *testing.T) {
	originalHost := os.Getenv("SERVER_HOST")
	originalPort := os.Getenv("SERVER_PORT")
	originalJWTSecret := os.Getenv("JWT_SECRET")

	defer func() {
		os.Setenv("SERVER_HOST", originalHost)
		os.Setenv("SERVER_PORT", originalPort)
		os.Setenv("JWT_SECRET", originalJWTSecret)
	}()

	os.Setenv("SERVER_HOST", "test-host")
	os.Setenv("SERVER_PORT", "9090")
	os.Setenv("JWT_SECRET", "test-secret")

	cfg := config.Load()

	if cfg.Server.Host != "test-host" {
		t.Errorf("Expected host 'test-host', got '%s'", cfg.Server.Host)
	}

	if cfg.Server.Port != "9090" {
		t.Errorf("Expected port '9090', got '%s'", cfg.Server.Port)
	}

	if cfg.Auth.JWTSecret != "test-secret" {
		t.Errorf("Expected JWT secret 'test-secret', got '%s'", cfg.Auth.JWTSecret)
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := config.Load()

	if cfg.Server.ReadTimeout == 0 {
		t.Error("Read timeout should have default value")
	}

	if cfg.Server.WriteTimeout == 0 {
		t.Error("Write timeout should have default value")
	}

	if cfg.Server.IdleTimeout == 0 {
		t.Error("Idle timeout should have default value")
	}

	if cfg.Auth.AccessTokenTTL == 0 {
		t.Error("Access token TTL should have default value")
	}

	if cfg.Auth.RefreshTokenTTL == 0 {
		t.Error("Refresh token TTL should have default value")
	}

	if cfg.Security.RateLimitRequests == 0 {
		t.Error("Rate limit requests should have default value")
	}
}

func TestConfigDurationParsing(t *testing.T) {
	originalTimeout := os.Getenv("READ_TIMEOUT")
	originalTokenTTL := os.Getenv("ACCESS_TOKEN_TTL")

	defer func() {
		os.Setenv("READ_TIMEOUT", originalTimeout)
		os.Setenv("ACCESS_TOKEN_TTL", originalTokenTTL)
	}()

	os.Setenv("READ_TIMEOUT", "30s")
	os.Setenv("ACCESS_TOKEN_TTL", "1h")

	cfg := config.Load()

	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("Expected read timeout 30s, got %v", cfg.Server.ReadTimeout)
	}

	if cfg.Auth.AccessTokenTTL != time.Hour {
		t.Errorf("Expected access token TTL 1h, got %v", cfg.Auth.AccessTokenTTL)
	}
}

func TestConfigInvalidDuration(t *testing.T) {
	originalTimeout := os.Getenv("READ_TIMEOUT")
	defer os.Setenv("READ_TIMEOUT", originalTimeout)

	os.Setenv("READ_TIMEOUT", "invalid-duration")
	cfg := config.Load()

	if cfg.Server.ReadTimeout != 10*time.Second {
		t.Errorf("Expected default read timeout 10s for invalid duration, got %v", cfg.Server.ReadTimeout)
	}
}

func TestConfigIntegerParsing(t *testing.T) {
	originalRateLimit := os.Getenv("RATE_LIMIT_REQUESTS")
	defer os.Setenv("RATE_LIMIT_REQUESTS", originalRateLimit)

	os.Setenv("RATE_LIMIT_REQUESTS", "500")
	cfg := config.Load()

	if cfg.Security.RateLimitRequests != 500 {
		t.Errorf("Expected rate limit 500, got %d", cfg.Security.RateLimitRequests)
	}
}

func TestConfigInvalidInteger(t *testing.T) {
	originalRateLimit := os.Getenv("RATE_LIMIT_REQUESTS")
	defer os.Setenv("RATE_LIMIT_REQUESTS", originalRateLimit)

	os.Setenv("RATE_LIMIT_REQUESTS", "invalid-number")
	cfg := config.Load()

	if cfg.Security.RateLimitRequests != 100 {
		t.Errorf("Expected default rate limit 100 for invalid integer, got %d", cfg.Security.RateLimitRequests)
	}
}

func TestConfigAllowedOrigins(t *testing.T) {
	cfg := config.Load()

	if len(cfg.Security.AllowedOrigins) == 0 {
		t.Error("Allowed origins should not be empty")
	}

	if cfg.Security.AllowedOrigins[0] == "" {
		t.Error("First allowed origin should not be empty")
	}
}

func TestConfigDatabaseSettings(t *testing.T) {
	cfg := config.Load()

	if cfg.Database.Port == "" {
		t.Error("Database port should have default value")
	}

	if cfg.Database.User == "" {
		t.Error("Database user should have default value")
	}

	if cfg.Database.Name == "" {
		t.Error("Database name should have default value")
	}

	if cfg.Database.SSLMode == "" {
		t.Error("Database SSL mode should have default value")
	}
}