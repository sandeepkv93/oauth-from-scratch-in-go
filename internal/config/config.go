package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     AuthConfig
	Security SecurityConfig
}

type ServerConfig struct {
	Host         string
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	TLSCert      string
	TLSKey       string
	BaseURL      string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

type AuthConfig struct {
	JWTSecret           string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	AuthorizationCodeTTL time.Duration
}

type SecurityConfig struct {
	RateLimitRequests   int
	RateLimitWindow     time.Duration
	AllowedOrigins      []string
	BlockedIPs          []string
	MaxRequestSize      int64
	EnableCSRF          bool
	MinPasswordLength   int
	RequireHTTPS        bool
	JWTRotationInterval time.Duration
}

func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "localhost"),
			Port:         getEnv("SERVER_PORT", "8080"),
			ReadTimeout:  getDurationEnv("READ_TIMEOUT", 10*time.Second),
			WriteTimeout: getDurationEnv("WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:  getDurationEnv("IDLE_TIMEOUT", 60*time.Second),
			TLSCert:      getEnv("TLS_CERT", ""),
			TLSKey:       getEnv("TLS_KEY", ""),
			BaseURL:      getEnv("BASE_URL", ""),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", ""),
			Name:     getEnv("DB_NAME", "oauth_server"),
			SSLMode:  getEnv("DB_SSL_MODE", "disable"),
		},
		Auth: AuthConfig{
			JWTSecret:           getEnv("JWT_SECRET", generateRandomSecret()),
			AccessTokenTTL:      getDurationEnv("ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL:     getDurationEnv("REFRESH_TOKEN_TTL", 7*24*time.Hour),
			AuthorizationCodeTTL: getDurationEnv("AUTH_CODE_TTL", 10*time.Minute),
		},
		Security: SecurityConfig{
			RateLimitRequests:   getIntEnv("RATE_LIMIT_REQUESTS", 100),
			RateLimitWindow:     getDurationEnv("RATE_LIMIT_WINDOW", time.Minute),
			AllowedOrigins:      parseStringArray(getEnv("ALLOWED_ORIGINS", "*")),
			BlockedIPs:          parseStringArray(getEnv("BLOCKED_IPS", "")),
			MaxRequestSize:      getInt64Env("MAX_REQUEST_SIZE", 1024*1024),
			EnableCSRF:          getBoolEnv("ENABLE_CSRF", false),
			MinPasswordLength:   getIntEnv("MIN_PASSWORD_LENGTH", 8),
			RequireHTTPS:        getBoolEnv("REQUIRE_HTTPS", false),
			JWTRotationInterval: getDurationEnv("JWT_ROTATION_INTERVAL", 24*time.Hour),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getInt64Env(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func parseStringArray(value string) []string {
	if value == "" {
		return []string{}
	}
	if value == "*" {
		return []string{"*"}
	}
	return strings.Split(value, ",")
}

func generateRandomSecret() string {
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		return secret
	}
	
	log.Println("WARNING: JWT_SECRET not set, using default. Set JWT_SECRET environment variable in production!")
	return "your-very-secure-secret-key-change-this-in-production"
}