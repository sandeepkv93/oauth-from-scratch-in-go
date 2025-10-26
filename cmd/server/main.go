package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"oauth-server/internal/admin"
	"oauth-server/internal/auth"
	"oauth-server/internal/cache"
	"oauth-server/internal/config"
	"oauth-server/internal/db"
	"oauth-server/internal/dcr"
	"oauth-server/internal/handlers"
	"oauth-server/internal/logging"
	"oauth-server/internal/middleware"
	"oauth-server/internal/monitoring"
	"oauth-server/internal/oidc"
	"oauth-server/internal/ratelimit"
	"oauth-server/internal/scopes"
	"oauth-server/internal/security"
	"oauth-server/pkg/jwt"
	"oauth-server/pkg/jwks"

	"github.com/redis/go-redis/v9"
)

func main() {
	cfg := config.Load()

	// Initialize structured logger
	loggerCfg := &logging.Config{
		Level:        cfg.Logging.Level,
		Format:       cfg.Logging.Format,
		Caller:       cfg.Logging.Caller,
		TimeFormat:   time.RFC3339Nano,
		SamplingRate: cfg.Logging.SamplingRate,
	}
	logger := logging.New(loggerCfg)

	// Validate configuration before starting server
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("Configuration validation failed: %v", err)
	}

	logger.InfoEvent().
		Str("environment", string(cfg.Environment)).
		Str("log_level", cfg.Logging.Level).
		Str("log_format", cfg.Logging.Format).
		Msg("Starting OAuth server")

	database, err := db.NewDatabase(&cfg.Database)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to database")
	}
	defer database.Close()

	baseURL := cfg.Server.BaseURL
	if baseURL == "" {
		scheme := "http"
		if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
			scheme = "https"
		}
		baseURL = scheme + "://" + cfg.Server.Host + ":" + cfg.Server.Port
	}

	var jwtManager *jwt.Manager
	var keyManager *jwks.KeyManager
	
	useAsymmetricKeys := os.Getenv("USE_ASYMMETRIC_KEYS") == "true"
	if useAsymmetricKeys {
		var err error
		keyManager, err = jwks.NewKeyManager()
		if err != nil {
			logger.WithError(err).Fatal("Failed to create key manager")
		}
		jwtManager = jwt.NewManagerWithKeyManager(cfg.Auth.JWTSecret, keyManager)
		logger.Info("Using asymmetric JWT signing (RS256)")
	} else {
		jwtManager = jwt.NewManager(cfg.Auth.JWTSecret)
		logger.Info("Using symmetric JWT signing (HS256)")
	}

	// Initialize Redis client if enabled (shared for cache and rate limiting)
	var redisClient *redis.Client
	if cfg.Redis.Enabled {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
			PoolSize: cfg.Redis.PoolSize,
		})

		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			logger.WithError(err).Fatal("Failed to connect to Redis")
		}
		logger.InfoEvent().
			Str("host", cfg.Redis.Host).
			Str("port", cfg.Redis.Port).
			Msg("Connected to Redis")
	}

	// Initialize cache if enabled
	var cacheService cache.Cache
	if cfg.Cache.Enabled {
		if redisClient == nil {
			logger.Fatal("Cache enabled but Redis is not enabled")
		}
		cacheService = cache.NewRedisCache(redisClient)
		logger.Info("Cache enabled with Redis backend")
	}

	authService := auth.NewService(database, jwtManager, cfg, cacheService)
	metricsService := monitoring.NewService()
	oidcService := oidc.NewService(jwtManager, baseURL)
	
	// Setup scope management service
	scopeService := scopes.NewService(database)
	
	// Setup Dynamic Client Registration service
	dcrConfig := &dcr.Config{
		RegistrationEnabled:  true,
		DefaultScopes:        []string{"openid", "profile", "email"},
		DefaultGrantTypes:    []string{"authorization_code", "refresh_token"},
		DefaultResponseTypes: []string{"code"},
		BaseURL:             baseURL,
	}
	dcrService := dcr.NewService(database, scopeService, dcrConfig)
	
	// Setup Admin service
	adminConfig := &admin.Config{
		Version: "1.0.0",
	}
	adminService := admin.NewService(database, authService, scopeService, adminConfig)
	
	handler := handlers.NewHandler(authService, database, oidcService, dcrService, adminService)
	middlewareManager := middleware.NewMiddleware(authService, metricsService, logger)

	// Setup CSRF protection if enabled
	if cfg.Security.EnableCSRF {
		if cfg.Security.CSRFSecret == "" {
			logger.Fatal("CSRF enabled but CSRF_SECRET not set")
		}
		csrfManager := security.NewCSRFManager(cfg.Security.CSRFSecret, 24*time.Hour)
		middlewareManager.SetCSRFManager(csrfManager)
		logger.Info("CSRF protection enabled")
	}

	// Setup rate limiter based on configuration
	var rateLimiter ratelimit.RateLimiter
	rateLimitConfig := &ratelimit.Config{
		MaxRequests: cfg.Security.RateLimitRequests,
		Window:      cfg.Security.RateLimitWindow,
	}

	switch cfg.Security.RateLimitBackend {
	case "redis":
		if redisClient == nil {
			logger.Fatal("Rate limit backend set to 'redis' but Redis is not enabled")
		}

		rateLimiter = ratelimit.NewRedisRateLimiter(redisClient, rateLimitConfig)
		logger.Info("Using Redis rate limiter")

	case "memory":
		rateLimiter = ratelimit.NewMemoryRateLimiter(rateLimitConfig)
		logger.Warn("Using in-memory rate limiter (not suitable for distributed deployments)")

	default:
		logger.Fatalf("Invalid rate limit backend: %s (must be 'memory' or 'redis')", cfg.Security.RateLimitBackend)
	}

	middlewareManager.SetRateLimiter(rateLimiter)
	defer rateLimiter.Close()
	
	router := mux.NewRouter()
	
	router.Use(middlewareManager.Logger)
	router.Use(middlewareManager.CORS(cfg.Security.AllowedOrigins))
	router.Use(middlewareManager.SecurityHeadersEnhanced)
	router.Use(middlewareManager.PanicRecovery)
	router.Use(middlewareManager.RateLimit(cfg.Security.RateLimitRequests, cfg.Security.RateLimitWindow))
	router.Use(middlewareManager.RequestSizeLimit(cfg.Security.MaxRequestSize))
	
	if len(cfg.Security.BlockedIPs) > 0 {
		router.Use(middlewareManager.IPBlacklist(cfg.Security.BlockedIPs))
	}
	
	if cfg.Security.RequireHTTPS {
		router.Use(middlewareManager.RequireHTTPS)
	}
	
	handler.RegisterRoutes(router)
	
	router.HandleFunc("/health", metricsService.ServeHealthCheck).Methods("GET")
	router.HandleFunc("/metrics", metricsService.ServeMetrics).Methods("GET")
	router.HandleFunc("/.well-known/oauth-authorization-server", wellKnownOIDCEndpoint(oidcService, baseURL)).Methods("GET")
	router.HandleFunc("/.well-known/openid-configuration", wellKnownOIDCEndpoint(oidcService, baseURL)).Methods("GET")
	
	if keyManager != nil {
		router.HandleFunc("/.well-known/jwks.json", jwksEndpoint(keyManager)).Methods("GET")
	}
	
	srv := &http.Server{
		Addr:         cfg.Server.Host + ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		logger.InfoEvent().
			Str("host", cfg.Server.Host).
			Str("port", cfg.Server.Port).
			Msg("OAuth server starting")
		if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
			logger.Info("Using HTTPS with TLS certificates")
			if err := srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Fatal("Failed to start HTTPS server")
			}
		} else {
			logger.Warn("Using HTTP without TLS - insecure for production!")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Fatal("Failed to start server")
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server forced to shutdown")
	}

	logger.Info("Server exited")
}


func wellKnownOIDCEndpoint(oidcService *oidc.Service, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := oidcService.GetWellKnownConfiguration(baseURL)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger := logging.FromContext(r.Context())
			logger.WithError(err).Error("Error encoding well-known response")
		}
	}
}

func jwksEndpoint(keyManager *jwks.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwkSet := keyManager.GetJWKSet()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(jwkSet); err != nil {
			logger := logging.FromContext(r.Context())
			logger.WithError(err).Error("Error encoding JWKS response")
		}
	}
}