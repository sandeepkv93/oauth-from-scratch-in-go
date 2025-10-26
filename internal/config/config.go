package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

type Config struct {
	Environment Environment
	Server      ServerConfig
	Database    DatabaseConfig
	Auth        AuthConfig
	Security    SecurityConfig
	Redis       RedisConfig
	Cache       CacheConfig
	Logging     LoggingConfig
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
	Host            string
	Port            string
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	QueryTimeout    time.Duration
}

type AuthConfig struct {
	JWTSecret           string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	AuthorizationCodeTTL time.Duration
}

type SecurityConfig struct {
	RateLimitRequests      int
	RateLimitWindow        time.Duration
	RateLimitBackend       string // "memory" or "redis"
	AllowedOrigins         []string
	BlockedIPs             []string
	MaxRequestSize         int64
	EnableCSRF             bool
	CSRFSecret             string
	MinPasswordLength      int
	RequireHTTPS           bool
	JWTRotationInterval    time.Duration
	PwnedPasswordsEnabled  bool
	PwnedPasswordsTimeout  time.Duration
	PwnedPasswordsFailOpen bool // If true, allow password on API errors

	// Client Secret Rotation
	SecretRotationEnabled      bool
	SecretMaxActiveSecrets     int
	SecretRotationPeriod       time.Duration
	SecretGracePeriod          time.Duration
	SecretAutoRotate           bool
	SecretNotifyBeforeExpiry   time.Duration
}

type RedisConfig struct {
	Enabled  bool
	Host     string
	Port     string
	Password string
	DB       int
	PoolSize int
}

type CacheConfig struct {
	Enabled         bool
	TokenTTL        time.Duration // How long to cache valid tokens
	UserTTL         time.Duration // How long to cache user data
	ClientTTL       time.Duration // How long to cache client data
	StatsEnabled    bool          // Enable cache statistics collection
}

type LoggingConfig struct {
	Level        string // debug, info, warn, error
	Format       string // json, console
	Caller       bool   // Include caller information
	SamplingRate int    // Sample 1 in N debug messages (0 = no sampling)
}

func Load() *Config {
	env := getEnvironment()

	cfg := &Config{
		Environment: env,
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
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnv("DB_PORT", "5432"),
			User:            getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", ""),
			Name:            getEnv("DB_NAME", "oauth_server"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getIntEnv("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getIntEnv("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getDurationEnv("DB_CONN_MAX_LIFETIME", 30*time.Minute),
			ConnMaxIdleTime: getDurationEnv("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
			QueryTimeout:    getDurationEnv("DB_QUERY_TIMEOUT", 30*time.Second),
		},
		Auth: AuthConfig{
			JWTSecret:            loadJWTSecret(env),
			AccessTokenTTL:       getDurationEnv("ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL:      getDurationEnv("REFRESH_TOKEN_TTL", 7*24*time.Hour),
			AuthorizationCodeTTL: getDurationEnv("AUTH_CODE_TTL", 10*time.Minute),
		},
		Security: SecurityConfig{
			RateLimitRequests:      getIntEnv("RATE_LIMIT_REQUESTS", 100),
			RateLimitWindow:        getDurationEnv("RATE_LIMIT_WINDOW", time.Minute),
			RateLimitBackend:       getEnv("RATE_LIMIT_BACKEND", "memory"),
			AllowedOrigins:         parseStringArray(getEnv("ALLOWED_ORIGINS", "*")),
			BlockedIPs:             parseStringArray(getEnv("BLOCKED_IPS", "")),
			MaxRequestSize:         getInt64Env("MAX_REQUEST_SIZE", 1024*1024),
			EnableCSRF:             getBoolEnv("ENABLE_CSRF", false),
			CSRFSecret:             getEnv("CSRF_SECRET", ""),
			MinPasswordLength:      getIntEnv("MIN_PASSWORD_LENGTH", 8),
			RequireHTTPS:           getBoolEnv("REQUIRE_HTTPS", false),
			JWTRotationInterval:    getDurationEnv("JWT_ROTATION_INTERVAL", 24*time.Hour),
			PwnedPasswordsEnabled:  getBoolEnv("PWNED_PASSWORDS_ENABLED", true), // Enabled by default for security
			PwnedPasswordsTimeout:  getDurationEnv("PWNED_PASSWORDS_TIMEOUT", 5*time.Second),
			PwnedPasswordsFailOpen: getBoolEnv("PWNED_PASSWORDS_FAIL_OPEN", true), // Fail open by default

			// Client Secret Rotation
			SecretRotationEnabled:      getBoolEnv("SECRET_ROTATION_ENABLED", true),      // Enabled by default for security
			SecretMaxActiveSecrets:     getIntEnv("SECRET_MAX_ACTIVE_SECRETS", 2),        // Keep current + 1 previous
			SecretRotationPeriod:       getDurationEnv("SECRET_ROTATION_PERIOD", 90*24*time.Hour), // 90 days
			SecretGracePeriod:          getDurationEnv("SECRET_GRACE_PERIOD", 7*24*time.Hour),     // 7 days
			SecretAutoRotate:           getBoolEnv("SECRET_AUTO_ROTATE", false),            // Manual rotation by default
			SecretNotifyBeforeExpiry:   getDurationEnv("SECRET_NOTIFY_BEFORE_EXPIRY", 14*24*time.Hour), // Notify 14 days before
		},
		Redis: RedisConfig{
			Enabled:  getBoolEnv("REDIS_ENABLED", false),
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getIntEnv("REDIS_DB", 0),
			PoolSize: getIntEnv("REDIS_POOL_SIZE", 10),
		},
		Cache: CacheConfig{
			Enabled:      getBoolEnv("CACHE_ENABLED", false), // Disabled by default, requires Redis
			TokenTTL:     getDurationEnv("CACHE_TOKEN_TTL", 5*time.Minute),  // Cache tokens for 5 minutes
			UserTTL:      getDurationEnv("CACHE_USER_TTL", 15*time.Minute),  // Cache users for 15 minutes
			ClientTTL:    getDurationEnv("CACHE_CLIENT_TTL", 30*time.Minute), // Cache clients for 30 minutes
			StatsEnabled: getBoolEnv("CACHE_STATS_ENABLED", true),            // Enable stats by default
		},
		Logging: LoggingConfig{
			Level:        getEnv("LOG_LEVEL", "info"),              // info by default
			Format:       getEnv("LOG_FORMAT", getDefaultLogFormat(env)), // json in prod, console in dev
			Caller:       getBoolEnv("LOG_CALLER", true),           // Include caller by default
			SamplingRate: getIntEnv("LOG_SAMPLING_RATE", 0),        // No sampling by default
		},
	}

	return cfg
}

// getDefaultLogFormat returns the default log format based on environment
func getDefaultLogFormat(env Environment) string {
	if env == EnvProduction {
		return "json"
	}
	return "console"
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

func getEnvironment() Environment {
	env := strings.ToLower(os.Getenv("ENVIRONMENT"))
	switch env {
	case "production", "prod":
		return EnvProduction
	case "staging", "stage":
		return EnvStaging
	case "development", "dev":
		return EnvDevelopment
	default:
		// Default to development if not specified
		return EnvDevelopment
	}
}

func loadJWTSecret(env Environment) string {
	secret := os.Getenv("JWT_SECRET")

	// In production, JWT_SECRET is required
	if env == EnvProduction && secret == "" {
		log.Fatal("FATAL: JWT_SECRET environment variable must be set in production environment")
	}

	// Check for insecure default values in production
	if env == EnvProduction && secret == "your-very-secure-secret-key-change-this-in-production" {
		log.Fatal("FATAL: Default JWT_SECRET detected in production environment")
	}

	// Warn if secret is too short in production
	if env == EnvProduction && len(secret) < 32 {
		log.Fatal("FATAL: JWT_SECRET must be at least 32 characters in production environment")
	}

	// In development/staging, use default if not set
	if secret == "" {
		log.Println("WARNING: JWT_SECRET not set, using default. This is only acceptable in development!")
		return "dev-secret-change-this-in-production-environments"
	}

	return secret
}

// Validate validates the configuration
func (c *Config) Validate() error {
	var errs []error

	if err := c.Server.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("server config: %w", err))
	}

	if err := c.Database.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("database config: %w", err))
	}

	if err := c.Auth.Validate(c.Environment); err != nil {
		errs = append(errs, fmt.Errorf("auth config: %w", err))
	}

	if err := c.Security.Validate(c.Environment); err != nil {
		errs = append(errs, fmt.Errorf("security config: %w", err))
	}

	if err := c.Redis.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("redis config: %w", err))
	}

	if err := c.Cache.Validate(&c.Redis); err != nil {
		errs = append(errs, fmt.Errorf("cache config: %w", err))
	}

	if err := c.Logging.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("logging config: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Validate validates server configuration
func (s *ServerConfig) Validate() error {
	// Validate port number
	port, err := strconv.Atoi(s.Port)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %s (must be 1-65535)", s.Port)
	}

	// If TLS cert is specified, key must also be specified
	if s.TLSCert != "" && s.TLSKey == "" {
		return errors.New("TLS certificate specified but TLS key is missing")
	}

	if s.TLSKey != "" && s.TLSCert == "" {
		return errors.New("TLS key specified but TLS certificate is missing")
	}

	// Verify TLS files exist if specified
	if s.TLSCert != "" {
		if _, err := os.Stat(s.TLSCert); os.IsNotExist(err) {
			return fmt.Errorf("TLS certificate file not found: %s", s.TLSCert)
		}
	}

	if s.TLSKey != "" {
		if _, err := os.Stat(s.TLSKey); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s", s.TLSKey)
		}
	}

	// Validate timeouts are positive
	if s.ReadTimeout <= 0 {
		return errors.New("read timeout must be positive")
	}

	if s.WriteTimeout <= 0 {
		return errors.New("write timeout must be positive")
	}

	if s.IdleTimeout <= 0 {
		return errors.New("idle timeout must be positive")
	}

	return nil
}

// Validate validates database configuration
func (d *DatabaseConfig) Validate() error {
	if d.Host == "" {
		return errors.New("database host is required")
	}

	if d.Name == "" {
		return errors.New("database name is required")
	}

	if d.User == "" {
		return errors.New("database user is required")
	}

	// Validate port number
	port, err := strconv.Atoi(d.Port)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid database port: %s (must be 1-65535)", d.Port)
	}

	// Validate connection pool settings
	if d.MaxOpenConns < 1 {
		return errors.New("max_open_conns must be at least 1")
	}

	if d.MaxIdleConns < 0 {
		return errors.New("max_idle_conns cannot be negative")
	}

	if d.MaxIdleConns > d.MaxOpenConns {
		return errors.New("max_idle_conns cannot exceed max_open_conns")
	}

	if d.ConnMaxLifetime < 0 {
		return errors.New("conn_max_lifetime cannot be negative")
	}

	if d.QueryTimeout <= 0 {
		return errors.New("query timeout must be positive")
	}

	return nil
}

// Validate validates auth configuration
func (a *AuthConfig) Validate(env Environment) error {
	if a.JWTSecret == "" {
		return errors.New("JWT secret is required")
	}

	// Enforce minimum secret length in production
	if env == EnvProduction && len(a.JWTSecret) < 32 {
		return errors.New("JWT secret must be at least 32 characters in production")
	}

	if a.AccessTokenTTL <= 0 {
		return errors.New("access token TTL must be positive")
	}

	if a.RefreshTokenTTL <= 0 {
		return errors.New("refresh token TTL must be positive")
	}

	if a.AuthorizationCodeTTL <= 0 {
		return errors.New("authorization code TTL must be positive")
	}

	// Refresh token should be longer than access token
	if a.RefreshTokenTTL <= a.AccessTokenTTL {
		return errors.New("refresh token TTL must be greater than access token TTL")
	}

	return nil
}

// Validate validates security configuration
func (s *SecurityConfig) Validate(env Environment) error {
	if s.RateLimitRequests <= 0 {
		return errors.New("rate limit requests must be positive")
	}

	if s.RateLimitWindow <= 0 {
		return errors.New("rate limit window must be positive")
	}

	if s.MaxRequestSize <= 0 {
		return errors.New("max request size must be positive")
	}

	if s.MinPasswordLength < 8 {
		return errors.New("minimum password length must be at least 8")
	}

	// Validate CSRF secret if CSRF is enabled
	if s.EnableCSRF && s.CSRFSecret == "" {
		return errors.New("CSRF secret is required when CSRF protection is enabled")
	}

	// Validate rate limit backend
	if s.RateLimitBackend != "memory" && s.RateLimitBackend != "redis" {
		return fmt.Errorf("rate_limit_backend must be 'memory' or 'redis', got: %s", s.RateLimitBackend)
	}

	// Recommend HTTPS in production
	if env == EnvProduction && !s.RequireHTTPS {
		log.Println("WARNING: REQUIRE_HTTPS is false in production environment - this is insecure!")
	}

	return nil
}

// Validate validates Redis configuration
func (r *RedisConfig) Validate() error {
	if !r.Enabled {
		return nil // Skip validation if Redis is disabled
	}

	if r.Host == "" {
		return errors.New("redis host is required when Redis is enabled")
	}

	// Validate port number
	port, err := strconv.Atoi(r.Port)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid redis port: %s (must be 1-65535)", r.Port)
	}

	if r.DB < 0 || r.DB > 15 {
		return fmt.Errorf("invalid redis DB: %d (must be 0-15)", r.DB)
	}

	if r.PoolSize < 1 {
		return errors.New("redis pool size must be at least 1")
	}

	return nil
}

// Validate validates Cache configuration
func (c *CacheConfig) Validate(redis *RedisConfig) error {
	if !c.Enabled {
		return nil // Skip validation if cache is disabled
	}

	// Cache requires Redis to be enabled
	if !redis.Enabled {
		return errors.New("cache requires Redis to be enabled (set REDIS_ENABLED=true)")
	}

	// Validate TTL values are positive
	if c.TokenTTL <= 0 {
		return errors.New("cache token TTL must be positive")
	}

	if c.UserTTL <= 0 {
		return errors.New("cache user TTL must be positive")
	}

	if c.ClientTTL <= 0 {
		return errors.New("cache client TTL must be positive")
	}

	return nil
}

// Validate validates Logging configuration
func (l *LoggingConfig) Validate() error {
	// Validate log level
	validLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	isValid := false
	for _, level := range validLevels {
		if l.Level == level {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid log level: %s (must be one of: debug, info, warn, error, fatal, panic)", l.Level)
	}

	// Validate log format
	if l.Format != "json" && l.Format != "console" {
		return fmt.Errorf("invalid log format: %s (must be 'json' or 'console')", l.Format)
	}

	// Validate sampling rate
	if l.SamplingRate < 0 {
		return errors.New("log sampling rate cannot be negative")
	}

	return nil
}