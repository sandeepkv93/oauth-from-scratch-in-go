package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"oauth-server/internal/auth"
	"oauth-server/internal/config"
	"oauth-server/internal/db"
	"oauth-server/internal/handlers"
	"oauth-server/internal/middleware"
	"oauth-server/internal/monitoring"
	"oauth-server/internal/oidc"
	"oauth-server/pkg/jwt"
	"oauth-server/pkg/jwks"
)

func main() {
	cfg := config.Load()
	
	database, err := db.NewDatabase(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
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
			log.Fatalf("Failed to create key manager: %v", err)
		}
		jwtManager = jwt.NewManagerWithKeyManager(cfg.Auth.JWTSecret, keyManager)
		log.Println("Using asymmetric JWT signing (RS256)")
	} else {
		jwtManager = jwt.NewManager(cfg.Auth.JWTSecret)
		log.Println("Using symmetric JWT signing (HS256)")
	}
	
	authService := auth.NewService(database, jwtManager, cfg)
	metricsService := monitoring.NewService()
	oidcService := oidc.NewService(jwtManager, baseURL)
	
	handler := handlers.NewHandler(authService, database)
	middlewareManager := middleware.NewMiddleware(authService, metricsService)
	
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
		log.Printf("OAuth server starting on %s:%s", cfg.Server.Host, cfg.Server.Port)
		if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
			log.Printf("Using HTTPS with TLS certificates")
			if err := srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start HTTPS server: %v", err)
			}
		} else {
			log.Printf("WARNING: Using HTTP without TLS. This is insecure for production!")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start server: %v", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}


func wellKnownOIDCEndpoint(oidcService *oidc.Service, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := oidcService.GetWellKnownConfiguration(baseURL)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding well-known response: %v", err)
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
			log.Printf("Error encoding JWKS response: %v", err)
		}
	}
}