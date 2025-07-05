package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"oauth-server/internal/auth"
	"oauth-server/internal/db"
	"oauth-server/internal/oidc"
	"oauth-server/pkg/jwt"
)

func TestOIDCLogoutEndpoint(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/logout", nil)
	rr := httptest.NewRecorder()

	handler.Logout(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	if !strings.Contains(rr.Body.String(), "Sign Out") {
		t.Error("Logout page should contain 'Sign Out'")
	}
}

func TestOIDCLogoutWithRedirect(t *testing.T) {
	handler, _, _ := setupTestHandler()

	form := url.Values{}
	form.Add("action", "logout")
	form.Add("post_logout_redirect_uri", "http://example.com/logout")
	form.Add("state", "test-state")

	req := httptest.NewRequest("POST", "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Logout(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "http://example.com/logout") {
		t.Errorf("Expected redirect to logout URI, got %s", location)
	}

	if !strings.Contains(location, "state=test-state") {
		t.Error("Expected state parameter in redirect")
	}
}

func TestOIDCSessionCheck(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/session/check?client_id=test&session_state=abc123", nil)
	rr := httptest.NewRecorder()

	handler.CheckSession(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal("Failed to parse JSON response")
	}

	if response["client_id"] != "test" {
		t.Error("Expected client_id in response")
	}

	if response["session_state"] != "abc123" {
		t.Error("Expected session_state in response")
	}
}

func TestOIDCSessionIframe(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/session/iframe", nil)
	rr := httptest.NewRecorder()

	handler.SessionIframe(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	if !strings.Contains(rr.Body.String(), "receiveMessage") {
		t.Error("Session iframe should contain message handler")
	}

	if rr.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("Expected X-Frame-Options: SAMEORIGIN header")
	}
}

func TestEnhancedUserInfoEndpoint(t *testing.T) {
	handler, authService, _ := setupTestHandler()

	tokenResp, err := authService.ResourceOwnerPasswordCredentialsGrant(&auth.TokenRequest{
		GrantType:    "password",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Username:     "testuser",
		Password:     "testpassword",
		Scope:        "openid profile email",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	rr := httptest.NewRecorder()

	handler.UserInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal("Failed to parse JSON response")
	}

	if response["sub"] == nil {
		t.Error("UserInfo response should contain 'sub' claim")
	}
}

func TestUserInfoWithoutOpenIDScope(t *testing.T) {
	handler, authService, _ := setupTestHandler()

	tokenResp, err := authService.ClientCredentialsGrant(&auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read write",
	})
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	rr := httptest.NewRecorder()

	handler.UserInfo(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rr.Code)
	}
}

func TestOIDCWellKnownConfigurationEnhanced(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	oidcService := oidc.NewService(jwtManager, "http://localhost:8080")

	config := oidcService.GetWellKnownConfiguration("http://localhost:8080")

	expectedEndpoints := []string{
		"end_session_endpoint",
		"check_session_iframe", 
		"device_authorization_endpoint",
	}

	for _, endpoint := range expectedEndpoints {
		if config[endpoint] == nil {
			t.Errorf("Expected %s in well-known configuration", endpoint)
		}
	}

	if config["frontchannel_logout_supported"] != true {
		t.Error("Expected frontchannel_logout_supported to be true")
	}

	scopes := config["scopes_supported"].([]string)
	expectedScopes := []string{"openid", "profile", "email", "address", "phone", "offline_access"}
	for _, expectedScope := range expectedScopes {
		found := false
		for _, scope := range scopes {
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

func TestOIDCPromptParameterValidation(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	oidcService := oidc.NewService(jwtManager, "http://localhost:8080")

	testCases := []struct {
		prompt   string
		expected []string
	}{
		{"", []string{}},
		{"login", []string{"login"}},
		{"none", []string{"none"}},
		{"login consent", []string{"login", "consent"}},
		{"invalid login", []string{"login"}},
		{"none login", []string{"none", "login"}},
	}

	for _, tc := range testCases {
		result := oidcService.ValidatePromptParameter(tc.prompt)
		if len(result) != len(tc.expected) {
			t.Errorf("For prompt '%s', expected %v, got %v", tc.prompt, tc.expected, result)
			continue
		}
		
		for i, expected := range tc.expected {
			if result[i] != expected {
				t.Errorf("For prompt '%s', expected %v, got %v", tc.prompt, tc.expected, result)
			}
		}
	}
}

func TestOIDCLogoutURLGeneration(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	oidcService := oidc.NewService(jwtManager, "http://localhost:8080")

	testCases := []struct {
		redirectURI string
		state       string
		expected    string
	}{
		{"", "", ""},
		{"http://example.com/logout", "", "http://example.com/logout"},
		{"http://example.com/logout", "test-state", "http://example.com/logout?state=test-state"},
		{"http://example.com/logout?existing=param", "test-state", "http://example.com/logout?existing=param&state=test-state"},
	}

	for _, tc := range testCases {
		result := oidcService.GenerateLogoutURL(tc.redirectURI, tc.state)
		if result != tc.expected {
			t.Errorf("For redirectURI '%s' and state '%s', expected '%s', got '%s'", 
				tc.redirectURI, tc.state, tc.expected, result)
		}
	}
}

func TestOIDCShouldPromptLogin(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	oidcService := oidc.NewService(jwtManager, "http://localhost:8080")

	authTime := time.Now().Add(-30 * time.Second)

	testCases := []struct {
		prompts  []string
		maxAge   int
		expected bool
	}{
		{[]string{}, 0, false},
		{[]string{"login"}, 0, true},
		{[]string{"none"}, 0, false},
		{[]string{"consent"}, 0, false},
		{[]string{}, 10, true}, // maxAge exceeded
		{[]string{}, 60, false}, // maxAge not exceeded
	}

	for _, tc := range testCases {
		result := oidcService.ShouldPromptLogin(tc.prompts, authTime, tc.maxAge)
		if result != tc.expected {
			t.Errorf("For prompts %v and maxAge %d, expected %t, got %t", 
				tc.prompts, tc.maxAge, tc.expected, result)
		}
	}
}

func TestIDTokenGeneration(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")
	oidcService := oidc.NewService(jwtManager, "http://localhost:8080")

	_, mockDB := setupTestAuth()

	var testUser *db.User
	for _, user := range mockDB.users {
		testUser = user
		break
	}

	if testUser == nil {
		t.Fatal("No test user found")
	}

	idToken, err := oidcService.GenerateIDToken(
		testUser, 
		"test-client", 
		"test-nonce", 
		time.Now(), 
		15*time.Minute,
	)

	if err != nil {
		t.Fatalf("Failed to generate ID token: %v", err)
	}

	if idToken == "" {
		t.Error("ID token should not be empty")
	}

	claims, err := jwtManager.ValidateAccessToken(idToken)
	if err != nil {
		t.Fatalf("Failed to validate ID token: %v", err)
	}

	if claims.Subject != testUser.ID.String() {
		t.Errorf("Expected subject %s, got %s", testUser.ID.String(), claims.Subject)
	}
}