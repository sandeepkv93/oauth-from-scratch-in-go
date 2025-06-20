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
	"oauth-server/pkg/jwt"
)

func main() {
	cfg := config.Load()
	
	database, err := db.NewDatabase(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	jwtManager := jwt.NewManager(cfg.Auth.JWTSecret)
	authService := auth.NewService(database, jwtManager, cfg)
	
	handler := handlers.NewHandler(authService, database)
	middlewareManager := middleware.NewMiddleware(authService)
	
	router := mux.NewRouter()
	
	router.Use(middlewareManager.Logger)
	router.Use(middlewareManager.CORS)
	router.Use(middlewareManager.SecurityHeaders)
	router.Use(middlewareManager.PanicRecovery)
	router.Use(middlewareManager.RateLimit(cfg.Security.RateLimitRequests, cfg.Security.RateLimitWindow))
	
	handler.RegisterRoutes(router)
	
	router.HandleFunc("/health", healthCheck).Methods("GET")
	router.HandleFunc("/.well-known/oauth-authorization-server", wellKnownEndpoint(cfg)).Methods("GET")
	
	srv := &http.Server{
		Addr:         cfg.Server.Host + ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		log.Printf("OAuth server starting on %s:%s", cfg.Server.Host, cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
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

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

func wellKnownEndpoint(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		baseURL := "http://" + cfg.Server.Host + ":" + cfg.Server.Port
		
		response := map[string]interface{}{
			"issuer":                        baseURL,
			"authorization_endpoint":        baseURL + "/authorize",
			"token_endpoint":               baseURL + "/token",
			"userinfo_endpoint":            baseURL + "/userinfo",
			"introspection_endpoint":       baseURL + "/introspect",
			"response_types_supported":     []string{"code"},
			"grant_types_supported":        []string{"authorization_code", "refresh_token", "client_credentials"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
			"scopes_supported":             []string{"openid", "profile", "email", "read", "write"},
			"claims_supported":             []string{"sub", "username", "email"},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding well-known response: %v", err)
		}
	}
}