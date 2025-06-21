package config

import "time"

func LoadTestConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "localhost",
			Port:         "18080",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     "5432",
			User:     "test",
			Password: "test",
			Name:     "test_oauth",
			SSLMode:  "disable",
		},
		Auth: AuthConfig{
			JWTSecret:            "test-secret-key-for-integration-testing",
			AccessTokenTTL:       15 * time.Minute,
			RefreshTokenTTL:      7 * 24 * time.Hour,
			AuthorizationCodeTTL: 10 * time.Minute,
		},
		Security: SecurityConfig{
			RateLimitRequests: 1000,
			RateLimitWindow:   time.Minute,
			AllowedOrigins:    []string{"*"},
		},
	}
}