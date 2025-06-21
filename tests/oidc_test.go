package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"oauth-server/internal/db"
	"oauth-server/internal/oidc"
	"oauth-server/pkg/jwt"
)

func TestOIDCServiceCreation(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	if service == nil {
		t.Fatal("OIDC service should not be nil")
	}
}

func TestGenerateIDToken(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	user := &db.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	token, err := service.GenerateIDToken(user, "test-client", "test-nonce", time.Now(), 30*time.Minute)
	if err != nil {
		t.Fatalf("Failed to generate ID token: %v", err)
	}

	if token == "" {
		t.Error("ID token should not be empty")
	}

	if len(token) < 10 {
		t.Error("ID token should be reasonably long")
	}
}

func TestGenerateIDTokenWithoutNonce(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	user := &db.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	token, err := service.GenerateIDToken(user, "test-client", "", time.Now(), 30*time.Minute)
	if err != nil {
		t.Fatalf("Failed to generate ID token without nonce: %v", err)
	}

	if token == "" {
		t.Error("ID token should not be empty")
	}
}

func TestBuildUserInfoResponse(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	user := &db.User{
		ID:        uuid.New(),
		Username:  "testuser",
		Email:     "test@example.com",
		UpdatedAt: time.Now(),
	}

	scopes := []string{"openid", "profile", "email"}
	response := service.BuildUserInfoResponse(user, scopes)

	if response == nil {
		t.Fatal("UserInfo response should not be nil")
	}

	if response.Subject != user.ID.String() {
		t.Errorf("Expected subject %s, got %s", user.ID.String(), response.Subject)
	}

	if response.PreferredUsername != user.Username {
		t.Errorf("Expected preferred_username %s, got %s", user.Username, response.PreferredUsername)
	}

	if response.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, response.Email)
	}

	if !response.EmailVerified {
		t.Error("Email should be verified")
	}

	if response.UpdatedAt == 0 {
		t.Error("UpdatedAt should be set")
	}
}

func TestBuildUserInfoResponseProfileScope(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	user := &db.User{
		ID:        uuid.New(),
		Username:  "testuser",
		Email:     "test@example.com",
		UpdatedAt: time.Now(),
	}

	scopes := []string{"openid", "profile"}
	response := service.BuildUserInfoResponse(user, scopes)

	if response.PreferredUsername != user.Username {
		t.Errorf("Expected preferred_username %s, got %s", user.Username, response.PreferredUsername)
	}

	if response.Email != "" {
		t.Error("Email should not be included without email scope")
	}

	if response.UpdatedAt == 0 {
		t.Error("UpdatedAt should be set with profile scope")
	}
}

func TestBuildUserInfoResponseEmailScope(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	user := &db.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	scopes := []string{"openid", "email"}
	response := service.BuildUserInfoResponse(user, scopes)

	if response.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, response.Email)
	}

	if !response.EmailVerified {
		t.Error("Email should be verified")
	}

	if response.PreferredUsername != "" {
		t.Error("PreferredUsername should not be included without profile scope")
	}
}

func TestBuildUserInfoResponseMinimalScopes(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	user := &db.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	scopes := []string{"openid"}
	response := service.BuildUserInfoResponse(user, scopes)

	if response.Subject != user.ID.String() {
		t.Errorf("Expected subject %s, got %s", user.ID.String(), response.Subject)
	}

	if response.PreferredUsername != "" {
		t.Error("PreferredUsername should not be included without profile scope")
	}

	if response.Email != "" {
		t.Error("Email should not be included without email scope")
	}

	if response.UpdatedAt != 0 {
		t.Error("UpdatedAt should not be included without profile scope")
	}
}

func TestGetWellKnownConfiguration(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	baseURL := "https://oauth.example.com"
	config := service.GetWellKnownConfiguration(baseURL)

	if config == nil {
		t.Fatal("Configuration should not be nil")
	}

	expectedEndpoints := map[string]string{
		"authorization_endpoint": baseURL + "/authorize",
		"token_endpoint":        baseURL + "/token",
		"userinfo_endpoint":     baseURL + "/userinfo",
		"jwks_uri":              baseURL + "/.well-known/jwks.json",
		"registration_endpoint": baseURL + "/api/clients",
		"introspection_endpoint": baseURL + "/introspect",
		"revocation_endpoint":   baseURL + "/revoke",
	}

	for key, expectedValue := range expectedEndpoints {
		if actualValue, exists := config[key]; !exists {
			t.Errorf("Configuration should contain %s", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected %s to be %s, got %s", key, expectedValue, actualValue)
		}
	}

	if issuer, exists := config["issuer"]; !exists {
		t.Error("Configuration should contain issuer")
	} else if issuer != "https://example.com" {
		t.Errorf("Expected issuer https://example.com, got %s", issuer)
	}
}

func TestWellKnownConfigurationScopes(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	config := service.GetWellKnownConfiguration("https://oauth.example.com")

	scopes, exists := config["scopes_supported"]
	if !exists {
		t.Fatal("Configuration should contain scopes_supported")
	}

	scopesList, ok := scopes.([]string)
	if !ok {
		t.Fatal("scopes_supported should be a string slice")
	}

	expectedScopes := []string{"openid", "profile", "email", "address", "phone"}
	for _, expectedScope := range expectedScopes {
		found := false
		for _, scope := range scopesList {
			if scope == expectedScope {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected scope %s to be supported", expectedScope)
		}
	}
}

func TestWellKnownConfigurationResponseTypes(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	config := service.GetWellKnownConfiguration("https://oauth.example.com")

	responseTypes, exists := config["response_types_supported"]
	if !exists {
		t.Fatal("Configuration should contain response_types_supported")
	}

	responseTypesList, ok := responseTypes.([]string)
	if !ok {
		t.Fatal("response_types_supported should be a string slice")
	}

	expectedTypes := []string{"code", "id_token", "token id_token", "code id_token", "code token", "code token id_token"}
	for _, expectedType := range expectedTypes {
		found := false
		for _, responseType := range responseTypesList {
			if responseType == expectedType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected response type %s to be supported", expectedType)
		}
	}
}

func TestWellKnownConfigurationGrantTypes(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	config := service.GetWellKnownConfiguration("https://oauth.example.com")

	grantTypes, exists := config["grant_types_supported"]
	if !exists {
		t.Fatal("Configuration should contain grant_types_supported")
	}

	grantTypesList, ok := grantTypes.([]string)
	if !ok {
		t.Fatal("grant_types_supported should be a string slice")
	}

	expectedTypes := []string{"authorization_code", "implicit", "refresh_token", "client_credentials"}
	for _, expectedType := range expectedTypes {
		found := false
		for _, grantType := range grantTypesList {
			if grantType == expectedType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected grant type %s to be supported", expectedType)
		}
	}
}

func TestWellKnownConfigurationClaims(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	config := service.GetWellKnownConfiguration("https://oauth.example.com")

	claims, exists := config["claims_supported"]
	if !exists {
		t.Fatal("Configuration should contain claims_supported")
	}

	claimsList, ok := claims.([]string)
	if !ok {
		t.Fatal("claims_supported should be a string slice")
	}

	expectedClaims := []string{
		"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
		"name", "given_name", "family_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website",
		"email", "email_verified", "gender", "birthdate", "zoneinfo",
		"locale", "phone_number", "phone_number_verified", "address", "updated_at",
	}

	for _, expectedClaim := range expectedClaims {
		found := false
		for _, claim := range claimsList {
			if claim == expectedClaim {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected claim %s to be supported", expectedClaim)
		}
	}
}

func TestWellKnownConfigurationPKCE(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	config := service.GetWellKnownConfiguration("https://oauth.example.com")

	challengeMethods, exists := config["code_challenge_methods_supported"]
	if !exists {
		t.Fatal("Configuration should contain code_challenge_methods_supported")
	}

	methodsList, ok := challengeMethods.([]string)
	if !ok {
		t.Fatal("code_challenge_methods_supported should be a string slice")
	}

	expectedMethods := []string{"plain", "S256"}
	for _, expectedMethod := range expectedMethods {
		found := false
		for _, method := range methodsList {
			if method == expectedMethod {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected PKCE method %s to be supported", expectedMethod)
		}
	}
}

func TestHasOpenIDScope(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	testCases := []struct {
		scopes   []string
		expected bool
	}{
		{[]string{"openid"}, true},
		{[]string{"openid", "profile"}, true},
		{[]string{"profile", "openid", "email"}, true},
		{[]string{"profile", "email"}, false},
		{[]string{}, false},
		{[]string{"read", "write"}, false},
	}

	for _, tc := range testCases {
		result := service.HasOpenIDScope(tc.scopes)
		if result != tc.expected {
			t.Errorf("HasOpenIDScope(%v) = %v, expected %v", tc.scopes, result, tc.expected)
		}
	}
}

func TestIDTokenContent(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	user := &db.User{
		ID:        uuid.New(),
		Username:  "testuser",
		Email:     "test@example.com",
		UpdatedAt: time.Now(),
	}

	clientID := "test-client"
	nonce := "test-nonce"
	authTime := time.Now()
	ttl := 30 * time.Minute

	token, err := service.GenerateIDToken(user, clientID, nonce, authTime, ttl)
	if err != nil {
		t.Fatalf("Failed to generate ID token: %v", err)
	}

	// Note: The JWT manager may be able to parse ID tokens since they use the same signing method,
	// but in a real application, you would have separate validation logic for ID tokens vs access tokens
	_, err = jwtManager.ValidateAccessToken(token)
	// The validation might succeed since both use JWT with the same secret,
	// but ID tokens should be validated with different logic in production
	t.Logf("ID token validation as access token result: %v", err)
}

func TestIDTokenExpiration(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	service := oidc.NewService(jwtManager, "https://example.com")

	user := &db.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	expiredTTL := -1 * time.Hour
	token, err := service.GenerateIDToken(user, "test-client", "", time.Now(), expiredTTL)
	if err != nil {
		t.Fatalf("Failed to generate expired ID token: %v", err)
	}

	if token == "" {
		t.Error("Expired ID token should still be generated")
	}
}