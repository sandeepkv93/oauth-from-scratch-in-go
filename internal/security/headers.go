package security

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// SecurityPolicy defines security headers for specific endpoints
type SecurityPolicy struct {
	CSP                string
	FrameOptions       string
	AllowInlineScripts bool
	CacheControl       string
}

// DefaultPolicy is the strictest policy used as fallback
var DefaultPolicy = SecurityPolicy{
	CSP:                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
	FrameOptions:       "DENY",
	AllowInlineScripts: false,
	CacheControl:       "no-store, no-cache, must-revalidate, private",
}

// EndpointPolicies maps endpoint patterns to security policies
var EndpointPolicies = map[string]SecurityPolicy{
	// OAuth Authorization Endpoint - Needs to render login form
	"/authorize": {
		CSP:                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: true, // For dynamic form handling
		CacheControl:       "no-store, no-cache, must-revalidate, private",
	},

	// Token Endpoint - API only, no UI
	"/token": {
		CSP:                "default-src 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: false,
		CacheControl:       "no-store, no-cache, must-revalidate, private",
	},

	// UserInfo Endpoint - API only
	"/userinfo": {
		CSP:                "default-src 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: false,
		CacheControl:       "no-store, no-cache, must-revalidate, private",
	},

	// Introspection Endpoint - API only
	"/introspect": {
		CSP:                "default-src 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: false,
		CacheControl:       "no-store, no-cache, must-revalidate, private",
	},

	// Revocation Endpoint - API only
	"/revoke": {
		CSP:                "default-src 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: false,
		CacheControl:       "no-store, no-cache, must-revalidate, private",
	},

	// Well-Known Endpoints - Public metadata, can be cached
	"/.well-known/": {
		CSP:                "default-src 'none'",
		FrameOptions:       "SAMEORIGIN", // Allow embedding metadata
		AllowInlineScripts: false,
		CacheControl:       "public, max-age=3600", // Cache for 1 hour
	},

	// JWKS Endpoint - Public keys, can be cached
	"/.well-known/jwks.json": {
		CSP:                "default-src 'none'",
		FrameOptions:       "SAMEORIGIN",
		AllowInlineScripts: false,
		CacheControl:       "public, max-age=3600",
	},

	// Health Check - Monitoring only
	"/health": {
		CSP:                "default-src 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: false,
		CacheControl:       "no-store, no-cache",
	},

	// Metrics - Monitoring only
	"/metrics": {
		CSP:                "default-src 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: false,
		CacheControl:       "no-store, no-cache",
	},

	// Device Authorization - User interaction required
	"/device": {
		CSP:                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: true,
		CacheControl:       "no-store, no-cache, must-revalidate, private",
	},

	// Dynamic Client Registration - API only
	"/register": {
		CSP:                "default-src 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: false,
		CacheControl:       "no-store, no-cache, must-revalidate, private",
	},

	// Admin Endpoints - UI with dashboard
	"/admin/": {
		CSP:                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
		FrameOptions:       "DENY",
		AllowInlineScripts: true, // Admin dashboard may need inline scripts
		CacheControl:       "no-store, no-cache, must-revalidate, private",
	},
}

// GetSecurityPolicy returns the appropriate security policy for a given path
func GetSecurityPolicy(path string) SecurityPolicy {
	// Exact match first
	if policy, ok := EndpointPolicies[path]; ok {
		return policy
	}

	// Prefix match for wildcards
	for pattern, policy := range EndpointPolicies {
		if strings.HasSuffix(pattern, "/") && strings.HasPrefix(path, pattern) {
			return policy
		}
	}

	// Default to most restrictive policy
	return DefaultPolicy
}

// GenerateCSPNonce generates a cryptographically secure nonce for CSP
func GenerateCSPNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// CSPReport represents a Content Security Policy violation report
type CSPReport struct {
	Document struct {
		URL      string `json:"url"`
		Referrer string `json:"referrer"`
	} `json:"document"`
	Violation struct {
		BlockedURI         string `json:"blocked-uri"`
		ColumnNumber       int    `json:"column-number"`
		Disposition        string `json:"disposition"`
		EffectiveDirective string `json:"effective-directive"`
		LineNumber         int    `json:"line-number"`
		OriginalPolicy     string `json:"original-policy"`
		SourceFile         string `json:"source-file"`
		StatusCode         int    `json:"status-code"`
		ViolatedDirective  string `json:"violated-directive"`
	} `json:"csp-report"`
}

// ApplyCSPNonce applies a nonce to a CSP policy string
func ApplyCSPNonce(csp, nonce string) string {
	// Add nonce to script-src if it exists
	if strings.Contains(csp, "script-src") {
		// Replace 'self' with 'self' 'nonce-XXX'
		csp = strings.Replace(csp, "script-src 'self'", "script-src 'self' 'nonce-"+nonce+"'", 1)
	}

	// Add nonce to style-src if it exists and we want to allow inline styles via nonce
	// Currently we use 'unsafe-inline' for styles, so we don't add nonce there

	return csp
}

// GetPermissionsPolicy returns the Permissions-Policy header value
func GetPermissionsPolicy() string {
	return "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), picture-in-picture=()"
}

// GetReferrerPolicy returns the Referrer-Policy header value
func GetReferrerPolicy() string {
	return "strict-origin-when-cross-origin"
}
