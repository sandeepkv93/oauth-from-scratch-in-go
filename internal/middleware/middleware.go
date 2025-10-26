package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"oauth-server/internal/auth"
	"oauth-server/internal/monitoring"
	"oauth-server/internal/ratelimit"
	"oauth-server/internal/security"
	"oauth-server/pkg/jwt"
)

type Middleware struct {
	auth        *auth.Service
	metrics     *monitoring.Service
	rateLimiter ratelimit.RateLimiter
	csrfManager *security.CSRFManager
}

func NewMiddleware(authService *auth.Service, metricsService *monitoring.Service) *Middleware {
	return &Middleware{
		auth:    authService,
		metrics: metricsService,
	}
}

// SetCSRFManager sets the CSRF manager for the middleware
func (m *Middleware) SetCSRFManager(csrfManager *security.CSRFManager) {
	m.csrfManager = csrfManager
}

// SetRateLimiter sets the rate limiter for the middleware
func (m *Middleware) SetRateLimiter(rateLimiter ratelimit.RateLimiter) {
	m.rateLimiter = rateLimiter
}

func (m *Middleware) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		m.metrics.IncrementRequests()
		m.metrics.IncrementActiveRequests()
		m.metrics.RecordEndpointRequest(r.URL.Path)
		
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		m.metrics.DecrementActiveRequests()
		m.metrics.RecordResponseTime(r.URL.Path, duration)
		
		clientIP := getClientIP(r)
		userAgent := r.Header.Get("User-Agent")
		
		sanitizedUserAgent := strings.ReplaceAll(userAgent, "\n", "")
		sanitizedUserAgent = strings.ReplaceAll(sanitizedUserAgent, "\r", "")
		if len(sanitizedUserAgent) > 200 {
			sanitizedUserAgent = sanitizedUserAgent[:200]
		}
		
		log.Printf("[%s] %s %s %d %v %s \"%s\"",
			start.Format("2006-01-02 15:04:05"),
			r.Method,
			r.URL.Path,
			wrapped.statusCode,
			duration,
			clientIP,
			sanitizedUserAgent,
		)
		
		if wrapped.statusCode >= 400 {
			log.Printf("[ERROR] %s %s returned %d from %s", r.Method, r.URL.Path, wrapped.statusCode, clientIP)
		}
	})
}

func (m *Middleware) CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowedOrigin := "*"
			
			if len(allowedOrigins) > 0 && allowedOrigins[0] != "*" {
				allowedOrigin = ""
				for _, allowed := range allowedOrigins {
					if allowed == origin {
						allowedOrigin = origin
						break
					}
				}
				if allowedOrigin == "" {
					allowedOrigin = allowedOrigins[0]
				}
			}
			
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "3600")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) RateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no rate limiter configured, skip
			if m.rateLimiter == nil {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := getClientIP(r)

			// Check rate limit
			result, err := m.rateLimiter.Allow(clientIP)
			if err != nil {
				log.Printf("Rate limit check failed: %v", err)
				// Fail open - allow request if rate limiter fails
				next.ServeHTTP(w, r)
				return
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetTime.Unix()))

			// Check if allowed
			if !result.Allowed {
				retryAfter := int(result.ResetTime.Sub(time.Now()).Seconds())
				if retryAfter < 0 {
					retryAfter = 0
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		claims, err := m.auth.ValidateAccessToken(token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value("claims").(*jwt.Claims)
			if !ok {
				http.Error(w, "No authentication context", http.StatusUnauthorized)
				return
			}

			hasScope := false
			for _, s := range claims.Scopes {
				if s == scope {
					hasScope = true
					break
				}
			}

			if !hasScope {
				http.Error(w, fmt.Sprintf("Scope '%s' required", scope), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				clientIP := getClientIP(r)
				log.Printf("[PANIC] %v | %s %s | Client: %s | User-Agent: %s", err, r.Method, r.URL.Path, clientIP, r.Header.Get("User-Agent"))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	return ""
}

func (m *Middleware) CSRFProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = r.FormValue("csrf_token")
			}
			
			if csrfToken == "" {
				http.Error(w, "CSRF token required", http.StatusForbidden)
				return
			}
			
			if !m.validateCSRFToken(csrfToken) {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) validateCSRFToken(token string) bool {
	// If CSRF manager not configured, fail closed for security
	if m.csrfManager == nil {
		log.Println("WARNING: CSRF validation requested but CSRF manager not configured")
		return false
	}

	// Extract session ID from context or use a default
	// In a real implementation, this would come from the session
	sessionID := "default-session" // TODO: Extract from actual session

	err := m.csrfManager.ValidateToken(token, sessionID)
	if err != nil {
		log.Printf("CSRF validation failed: %v", err)
		return false
	}

	return true
}

func (m *Middleware) RequestSizeLimit(maxSize int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxSize {
				http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
				return
			}
			
			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) SecurityHeadersEnhanced(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

		// Get security policy for this endpoint
		policy := security.GetSecurityPolicy(r.URL.Path)

		// Standard security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", policy.FrameOptions)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", security.GetReferrerPolicy())
		w.Header().Set("Permissions-Policy", security.GetPermissionsPolicy())

		// Cache control based on endpoint policy
		w.Header().Set("Cache-Control", policy.CacheControl)
		if !strings.Contains(policy.CacheControl, "public") {
			// Only set these for private content
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		// Content Security Policy with optional nonce
		csp := policy.CSP
		if policy.AllowInlineScripts {
			// Generate CSP nonce for inline scripts
			nonce, err := security.GenerateCSPNonce()
			if err == nil {
				csp = security.ApplyCSPNonce(csp, nonce)
				// Store nonce in context for templates to use
				ctx := context.WithValue(r.Context(), "csp-nonce", nonce)
				r = r.WithContext(ctx)
			}
		}
		w.Header().Set("Content-Security-Policy", csp)

		// HSTS only on HTTPS connections
		if isHTTPS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) IPBlacklist(blockedIPs []string) func(http.Handler) http.Handler {
	blockedSet := make(map[string]bool)
	for _, ip := range blockedIPs {
		blockedSet[ip] = true
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			
			if blockedSet[clientIP] {
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) RequireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			httpsURL := "https://" + r.Host + r.RequestURI
			http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func getClientIP(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		if net.ParseIP(xRealIP) != nil {
			return xRealIP
		}
	}
	
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	
	return ip
}