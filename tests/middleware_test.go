package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"oauth-server/internal/auth"
	"oauth-server/internal/logging"
	"oauth-server/internal/middleware"
	"oauth-server/internal/monitoring"
)

// Helper function to create middleware with test logger
func setupTestMiddleware(authService *auth.Service, metricsService *monitoring.Service) *middleware.Middleware {
	testLogger := logging.New(&logging.Config{
		Level:  "error", // Use error level to reduce test output noise
		Format: "console",
		Caller: false,
	})
	return middleware.NewMiddleware(authService, metricsService, testLogger)
}

func TestMiddlewareCreation(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()

	middleware := setupTestMiddleware(authService, metricsService)
	if middleware == nil {
		t.Fatal("Middleware should not be nil")
	}
}

func TestLoggerMiddleware(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	wrappedHandler := middlewareManager.Logger(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	if rr.Body.String() != "test response" {
		t.Errorf("Expected 'test response', got %s", rr.Body.String())
	}

	metrics := metricsService.GetMetrics()
	if metrics.TotalRequests == 0 {
		t.Error("Logger middleware should increment total requests")
	}

	if metrics.RequestsByEndpoint["/test"] == 0 {
		t.Error("Logger middleware should record endpoint requests")
	}
}

func TestCORSMiddleware(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middlewareManager.CORS([]string{"*"})(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	expectedHeaders := map[string]string{
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization",
		"Access-Control-Max-Age":       "3600",
		"Access-Control-Allow-Credentials": "true",
	}

	for header, expectedValue := range expectedHeaders {
		actualValue := rr.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("Expected %s header '%s', got '%s'", header, expectedValue, actualValue)
		}
	}
}

func TestCORSOptionsRequest(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for OPTIONS request")
	})

	wrappedHandler := middlewareManager.CORS([]string{"*"})(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rr.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitedHandler := middlewareManager.RateLimit(2, time.Minute)(handler)

	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	rr1 := httptest.NewRecorder()

	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	rr2 := httptest.NewRecorder()

	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = "192.168.1.1:12345"
	rr3 := httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("First request should succeed, got %d", rr1.Code)
	}

	rateLimitedHandler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("Second request should succeed, got %d", rr2.Code)
	}

	rateLimitedHandler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusTooManyRequests {
		t.Errorf("Third request should be rate limited, got %d", rr3.Code)
	}
}

func TestRateLimitDifferentIPs(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitedHandler := middlewareManager.RateLimit(1, time.Minute)(handler)

	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	rr1 := httptest.NewRecorder()

	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.2:12345"
	rr2 := httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("First IP should succeed, got %d", rr1.Code)
	}

	rateLimitedHandler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("Second IP should succeed, got %d", rr2.Code)
	}
}

func TestRequireAuthMiddleware(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := middlewareManager.RequireAuth(handler)

	req := httptest.NewRequest("GET", "/protected", nil)
	rr := httptest.NewRecorder()

	authHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Request without token should return 401, got %d", rr.Code)
	}

	if !strings.Contains(rr.Body.String(), "Bearer token required") {
		t.Error("Response should indicate bearer token required")
	}
}

func TestRequireAuthWithValidToken(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	response, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value("claims")
		if claims == nil {
			t.Error("Claims should be available in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	authHandler := middlewareManager.RequireAuth(handler)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+response.AccessToken)
	rr := httptest.NewRecorder()

	authHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Request with valid token should succeed, got %d", rr.Code)
	}
}

func TestRequireScopeMiddleware(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	response, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read write",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	scopeHandler := middlewareManager.RequireAuth(middlewareManager.RequireScope("read")(handler))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+response.AccessToken)
	rr := httptest.NewRecorder()

	scopeHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Request with required scope should succeed, got %d", rr.Code)
	}
}

func TestRequireScopeInsufficientScope(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	response, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	scopeHandler := middlewareManager.RequireAuth(middlewareManager.RequireScope("admin")(handler))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+response.AccessToken)
	rr := httptest.NewRecorder()

	scopeHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Request without required scope should return 403, got %d", rr.Code)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := middlewareManager.SecurityHeadersEnhanced(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	secureHandler.ServeHTTP(rr, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":           "nosniff",
		"X-Frame-Options":                  "DENY",
		"X-XSS-Protection":                 "1; mode=block",
		"Referrer-Policy":                  "strict-origin-when-cross-origin",
		"Content-Security-Policy":          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
		"Permissions-Policy":               "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
		"Cache-Control":                    "no-store, no-cache, must-revalidate, private",
		"Pragma":                           "no-cache",
		"Expires":                          "0",
	}

	for header, expectedValue := range expectedHeaders {
		actualValue := rr.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("Expected %s header '%s', got '%s'", header, expectedValue, actualValue)
		}
	}
}

func TestPanicRecoveryMiddleware(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	recoveryHandler := middlewareManager.PanicRecovery(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	recoveryHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Panic should result in 500 status, got %d", rr.Code)
	}

	if !strings.Contains(rr.Body.String(), "Internal server error") {
		t.Error("Response should contain error message")
	}
}

func TestResponseWriterStatusTracking(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	wrappedHandler := middlewareManager.Logger(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestBearerTokenExtraction(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token-123")

	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	authHandler := middlewareManager.RequireAuth(handler)
	rr := httptest.NewRecorder()

	authHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Invalid token should return 401, got %d", rr.Code)
	}
}

func TestInvalidAuthorizationHeader(t *testing.T) {
	authService, _ := setupTestAuth()
	metricsService := monitoring.NewService()
	middlewareManager := setupTestMiddleware(authService, metricsService)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := middlewareManager.RequireAuth(handler)

	testCases := []string{
		"Basic dGVzdDp0ZXN0",
		"Bearer",
		"Invalid header",
		"",
	}

	for _, authHeader := range testCases {
		req := httptest.NewRequest("GET", "/test", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		rr := httptest.NewRecorder()

		authHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Invalid authorization header '%s' should return 401, got %d", authHeader, rr.Code)
		}
	}
}