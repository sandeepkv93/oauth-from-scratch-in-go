package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/auth"
	"oauth-server/internal/db"
)

func TestJWTBearerGrant(t *testing.T) {
	authService, mockDB := setupTestAuth()

	// Create a client that supports JWT Bearer grant
	clientSecret := "jwt-bearer-secret"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	jwtClient := &db.Client{
		ClientID:     "jwt-bearer-client",
		ClientSecret: string(hashedSecret),
		Name:         "JWT Bearer Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"read", "write", "admin"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		IsPublic:     false,
	}
	mockDB.CreateClient(jwtClient)

	// Create JWT assertion
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "jwt-bearer-client",
		"sub": uuid.New().String(),
		"aud": "http://localhost:8080/token",
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	assertion, err := token.SignedString([]byte(clientSecret))
	if err != nil {
		t.Fatalf("Failed to create assertion: %v", err)
	}

	req := &auth.TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
		Assertion: assertion,
		Scope:     "read write",
	}

	response, err := authService.JWTBearerGrant(req)
	if err != nil {
		t.Errorf("Expected successful JWT Bearer grant, got error: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}
	if response.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}
	if response.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", response.TokenType)
	}
}

func TestJWTBearerGrantInvalidAssertion(t *testing.T) {
	authService, mockDB := setupTestAuth()
	
	// Create the jwt-bearer-client that the test assertions reference
	clientSecret := "jwt-bearer-secret"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	jwtClient := &db.Client{
		ClientID:     "jwt-bearer-client",
		ClientSecret: string(hashedSecret),
		Name:         "JWT Bearer Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		IsPublic:     false,
	}
	mockDB.CreateClient(jwtClient)

	testCases := []struct {
		name      string
		assertion string
		expected  string
	}{
		{
			name:      "Empty assertion",
			assertion: "",
			expected:  "assertion required",
		},
		{
			name:      "Invalid JWT format",
			assertion: "not-a-jwt",
			expected:  "invalid assertion",
		},
		{
			name:      "Invalid signature",
			assertion: func() string {
				// Create a JWT with current timestamps but invalid signature
				now := time.Now()
				claims := jwt.MapClaims{
					"iss": "jwt-bearer-client",
					"sub": "test-subject",
					"aud": "http://localhost:8080/token",
					"exp": now.Add(5 * time.Minute).Unix(),
					"iat": now.Unix(),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				validJWT, _ := token.SignedString([]byte("wrong-secret"))
				// Replace the signature part with invalid signature
				parts := strings.Split(validJWT, ".")
				return parts[0] + "." + parts[1] + ".invalid-signature"
			}(),
			expected:  "assertion signature verification failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &auth.TokenRequest{
				GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
				Assertion: tc.assertion,
			}

			_, err := authService.JWTBearerGrant(req)
			if err == nil {
				t.Error("Expected error, got nil")
			} else if err.Error() != tc.expected {
				t.Errorf("Expected error '%s', got '%s'", tc.expected, err.Error())
			}
		})
	}
}

func TestJWTBearerGrantExpiredAssertion(t *testing.T) {
	authService, mockDB := setupTestAuth()

	// Create a client
	clientSecret := "jwt-bearer-secret"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	jwtClient := &db.Client{
		ClientID:     "jwt-bearer-client",
		ClientSecret: string(hashedSecret),
		Name:         "JWT Bearer Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		IsPublic:     false,
	}
	mockDB.CreateClient(jwtClient)

	// Create expired JWT assertion
	claims := jwt.MapClaims{
		"iss": "jwt-bearer-client",
		"sub": uuid.New().String(),
		"aud": "http://localhost:8080/token",
		"exp": time.Now().Add(-5 * time.Minute).Unix(), // Expired
		"iat": time.Now().Add(-10 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	assertion, _ := token.SignedString([]byte(clientSecret))

	req := &auth.TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
		Assertion: assertion,
	}

	_, err := authService.JWTBearerGrant(req)
	if err == nil {
		t.Error("Expected error for expired assertion")
	} else if err.Error() != "assertion expired" {
		t.Errorf("Expected 'assertion expired' error, got '%s'", err.Error())
	}
}

func TestJWTBearerGrantMissingClaims(t *testing.T) {
	authService, _ := setupTestAuth()

	testCases := []struct {
		name     string
		claims   jwt.MapClaims
		expected string
	}{
		{
			name: "Missing issuer",
			claims: jwt.MapClaims{
				"sub": "test-subject",
				"aud": "http://localhost:8080/token",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			expected: "missing issuer claim",
		},
		{
			name: "Missing subject",
			claims: jwt.MapClaims{
				"iss": "test-client",
				"aud": "http://localhost:8080/token",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			expected: "missing subject claim",
		},
		{
			name: "Missing expiration",
			claims: jwt.MapClaims{
				"iss": "test-client",
				"sub": "test-subject",
				"aud": "http://localhost:8080/token",
				"iat": time.Now().Unix(),
			},
			expected: "missing expiration claim",
		},
		{
			name: "Missing issued at",
			claims: jwt.MapClaims{
				"iss": "test-client",
				"sub": "test-subject",
				"aud": "http://localhost:8080/token",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			},
			expected: "missing issued at claim",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, tc.claims)
			assertion, _ := token.SignedString([]byte("test-secret"))

			req := &auth.TokenRequest{
				GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
				Assertion: assertion,
			}

			_, err := authService.JWTBearerGrant(req)
			if err == nil {
				t.Error("Expected error, got nil")
			} else if err.Error() != tc.expected {
				t.Errorf("Expected error '%s', got '%s'", tc.expected, err.Error())
			}
		})
	}
}

func TestJWTBearerGrantInvalidAudience(t *testing.T) {
	authService, mockDB := setupTestAuth()

	// Create a client
	clientSecret := "jwt-bearer-secret"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	jwtClient := &db.Client{
		ClientID:     "jwt-bearer-client",
		ClientSecret: string(hashedSecret),
		Name:         "JWT Bearer Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		IsPublic:     false,
	}
	mockDB.CreateClient(jwtClient)

	// Create JWT with invalid audience
	claims := jwt.MapClaims{
		"iss": "jwt-bearer-client",
		"sub": uuid.New().String(),
		"aud": "https://different-server.com/token", // Invalid audience
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	assertion, _ := token.SignedString([]byte(clientSecret))

	req := &auth.TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
		Assertion: assertion,
	}

	_, err := authService.JWTBearerGrant(req)
	if err == nil {
		t.Error("Expected error for invalid audience")
	} else if err.Error() != "invalid audience claim" {
		t.Errorf("Expected 'invalid audience claim' error, got '%s'", err.Error())
	}
}

func TestJWTBearerGrantWithUserSubject(t *testing.T) {
	authService, mockDB := setupTestAuth()

	// Get a test user
	var testUser *db.User
	for _, user := range mockDB.users {
		testUser = user
		break
	}

	// Create a client
	clientSecret := "jwt-bearer-secret"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	jwtClient := &db.Client{
		ClientID:     "jwt-bearer-client",
		ClientSecret: string(hashedSecret),
		Name:         "JWT Bearer Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"read", "write", "openid"},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		IsPublic:     false,
	}
	mockDB.CreateClient(jwtClient)

	// Create JWT with user ID as subject
	claims := jwt.MapClaims{
		"iss": "jwt-bearer-client",
		"sub": testUser.ID.String(), // Use actual user ID
		"aud": "http://localhost:8080/token",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	assertion, _ := token.SignedString([]byte(clientSecret))

	req := &auth.TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
		Assertion: assertion,
		Scope:     "read openid",
	}

	response, err := authService.JWTBearerGrant(req)
	if err != nil {
		t.Errorf("Expected successful JWT Bearer grant, got error: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}

	// Verify the access token contains user information
	claims2, err := authService.ValidateAccessToken(response.AccessToken)
	if err != nil {
		t.Errorf("Failed to validate access token: %v", err)
	}
	if claims2.UserID != testUser.ID {
		t.Errorf("Expected user ID %s, got %s", testUser.ID, claims2.UserID)
	}
}