package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"oauth-server/internal/auth"
	"oauth-server/internal/config"
	"oauth-server/internal/db"
	"oauth-server/internal/handlers"
	"oauth-server/internal/middleware"
	"oauth-server/internal/monitoring"
	"oauth-server/internal/oidc"
	"oauth-server/pkg/crypto"
	"oauth-server/pkg/jwt"
)

type IntegrationTestSuite struct {
	server         *httptest.Server
	authService    *auth.Service
	mockDB         *MockDB
	jwtManager     *jwt.Manager
	metricsService *monitoring.Service
	oidcService    *oidc.Service
}

func setupIntegrationTest() *IntegrationTestSuite {
	mockDatabase := NewMockDatabase()
	
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:            "test-secret-for-integration",
			AccessTokenTTL:       15 * time.Minute,
			RefreshTokenTTL:      7 * 24 * time.Hour,
			AuthorizationCodeTTL: 10 * time.Minute,
		},
		Security: config.SecurityConfig{
			RateLimitRequests: 1000,
			RateLimitWindow:   time.Minute,
		},
	}

	jwtManager := jwt.NewManager(cfg.Auth.JWTSecret)
	authService := auth.NewService(mockDatabase, jwtManager, cfg)
	metricsService := monitoring.NewService()
	oidcService := oidc.NewService(jwtManager, "http://localhost:8080")
	
	handler := handlers.NewHandler(authService, mockDatabase)
	middlewareManager := middleware.NewMiddleware(authService, metricsService)
	
	router := mux.NewRouter()
	router.Use(middlewareManager.Logger)
	router.Use(middlewareManager.CORS([]string{"*"}))
	
	handler.RegisterRoutes(router)
	
	router.HandleFunc("/health", metricsService.ServeHealthCheck).Methods("GET")
	router.HandleFunc("/metrics", metricsService.ServeMetrics).Methods("GET")
	router.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		response := oidcService.GetWellKnownConfiguration("http://localhost:8080")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")
	
	server := httptest.NewServer(router)
	
	setupTestData(mockDatabase, authService)
	
	return &IntegrationTestSuite{
		server:         server,
		authService:    authService,
		mockDB:         mockDatabase,
		jwtManager:     jwtManager,
		metricsService: metricsService,
		oidcService:    oidcService,
	}
}

func setupTestData(database *MockDB, authService *auth.Service) {
	hashedPassword, _ := authService.HashPassword("testpassword")
	
	testUser := &db.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: hashedPassword,
		Scopes:   []string{"openid", "profile", "email", "read", "write"},
	}
	database.CreateUser(testUser)
	
	testClient := &db.Client{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Name:         "Test Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"openid", "profile", "email", "read", "write"},
		GrantTypes:   []string{"authorization_code", "refresh_token", "client_credentials"},
		IsPublic:     false,
	}
	database.CreateClient(testClient)
	
	publicClient := &db.Client{
		ClientID:     "public-client",
		ClientSecret: "",
		Name:         "Public Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"openid", "profile", "email", "read"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		IsPublic:     true,
	}
	database.CreateClient(publicClient)
}

func (suite *IntegrationTestSuite) cleanup() {
	suite.server.Close()
}

func TestHealthEndpoint(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	resp, err := http.Get(suite.server.URL + "/health")
	if err != nil {
		t.Fatalf("Failed to make health request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var healthResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&healthResponse); err != nil {
		t.Fatalf("Failed to decode health response: %v", err)
	}

	if healthResponse["status"] != "healthy" {
		t.Errorf("Expected healthy status, got %v", healthResponse["status"])
	}
}

func TestWellKnownConfiguration(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	resp, err := http.Get(suite.server.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Failed to make well-known request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		t.Fatalf("Failed to decode config response: %v", err)
	}

	expectedEndpoints := []string{
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"introspection_endpoint",
		"revocation_endpoint",
	}

	for _, endpoint := range expectedEndpoints {
		if _, exists := config[endpoint]; !exists {
			t.Errorf("Missing endpoint in configuration: %s", endpoint)
		}
	}
}

func TestClientCredentialsFlow(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")
	data.Set("scope", "read write")

	resp, err := http.PostForm(suite.server.URL+"/token", data)
	if err != nil {
		t.Fatalf("Failed to make token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}

	var tokenResponse auth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResponse.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}

	if tokenResponse.TokenType != "Bearer" {
		t.Errorf("Expected token type Bearer, got %s", tokenResponse.TokenType)
	}

	if tokenResponse.ExpiresIn <= 0 {
		t.Errorf("Expected positive expires_in, got %d", tokenResponse.ExpiresIn)
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	code := suite.createAuthorizationCode(t)
	
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	resp, err := http.PostForm(suite.server.URL+"/token", data)
	if err != nil {
		t.Fatalf("Failed to make token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}

	var tokenResponse auth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResponse.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}

	if tokenResponse.RefreshToken == "" {
		t.Error("Expected non-empty refresh token")
	}
}

func TestPKCEFlow(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	pkce := crypto.NewPKCEManager()
	verifier, _ := pkce.GenerateCodeVerifier()
	challenge, _ := pkce.GenerateCodeChallenge(verifier, "S256")

	code := suite.createAuthorizationCodeWithPKCE(t, challenge, "S256")
	
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("client_id", "public-client")
	data.Set("code_verifier", verifier)

	resp, err := http.PostForm(suite.server.URL+"/token", data)
	if err != nil {
		t.Fatalf("Failed to make token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}

	var tokenResponse auth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResponse.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	code := suite.createAuthorizationCode(t)
	
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	resp, err := http.PostForm(suite.server.URL+"/token", data)
	if err != nil {
		t.Fatalf("Failed to make initial token request: %v", err)
	}
	defer resp.Body.Close()

	var initialTokenResponse auth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&initialTokenResponse); err != nil {
		t.Fatalf("Failed to decode initial token response: %v", err)
	}

	refreshData := url.Values{}
	refreshData.Set("grant_type", "refresh_token")
	refreshData.Set("refresh_token", initialTokenResponse.RefreshToken)
	refreshData.Set("client_id", "test-client")
	refreshData.Set("client_secret", "test-secret")

	refreshResp, err := http.PostForm(suite.server.URL+"/token", refreshData)
	if err != nil {
		t.Fatalf("Failed to make refresh token request: %v", err)
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("Expected status 200 for refresh, got %d. Body: %s", refreshResp.StatusCode, string(body))
	}

	var refreshTokenResponse auth.TokenResponse
	if err := json.NewDecoder(refreshResp.Body).Decode(&refreshTokenResponse); err != nil {
		t.Fatalf("Failed to decode refresh token response: %v", err)
	}

	if refreshTokenResponse.AccessToken == "" {
		t.Error("Expected non-empty access token from refresh")
	}

	if refreshTokenResponse.AccessToken == initialTokenResponse.AccessToken {
		t.Error("Refreshed access token should be different from original")
	}
}

func TestTokenIntrospection(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")
	data.Set("scope", "read")

	resp, err := http.PostForm(suite.server.URL+"/token", data)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer resp.Body.Close()

	var tokenResponse auth.TokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenResponse)

	introspectData := url.Values{}
	introspectData.Set("token", tokenResponse.AccessToken)

	introspectResp, err := http.PostForm(suite.server.URL+"/introspect", introspectData)
	if err != nil {
		t.Fatalf("Failed to introspect token: %v", err)
	}
	defer introspectResp.Body.Close()

	if introspectResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", introspectResp.StatusCode)
	}

	var introspectResponse map[string]interface{}
	if err := json.NewDecoder(introspectResp.Body).Decode(&introspectResponse); err != nil {
		t.Fatalf("Failed to decode introspect response: %v", err)
	}

	if introspectResponse["active"] != true {
		t.Error("Expected token to be active")
	}

	if introspectResponse["client_id"] != "test-client" {
		t.Errorf("Expected client_id test-client, got %v", introspectResponse["client_id"])
	}
}

func TestTokenRevocation(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	resp, err := http.PostForm(suite.server.URL+"/token", data)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer resp.Body.Close()

	var tokenResponse auth.TokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenResponse)

	revokeData := url.Values{}
	revokeData.Set("token", tokenResponse.AccessToken)
	revokeData.Set("client_id", "test-client")
	revokeData.Set("client_secret", "test-secret")

	revokeResp, err := http.PostForm(suite.server.URL+"/revoke", revokeData)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}
	defer revokeResp.Body.Close()

	if revokeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(revokeResp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", revokeResp.StatusCode, string(body))
	}

	introspectData := url.Values{}
	introspectData.Set("token", tokenResponse.AccessToken)

	introspectResp, err := http.PostForm(suite.server.URL+"/introspect", introspectData)
	if err != nil {
		t.Fatalf("Failed to introspect revoked token: %v", err)
	}
	defer introspectResp.Body.Close()

	var introspectResponse map[string]interface{}
	json.NewDecoder(introspectResp.Body).Decode(&introspectResponse)

	if introspectResponse["active"] != false {
		t.Error("Expected revoked token to be inactive")
	}
}

func TestUserInfoEndpoint(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	code := suite.createAuthorizationCode(t)
	
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	resp, err := http.PostForm(suite.server.URL+"/token", data)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer resp.Body.Close()

	var tokenResponse auth.TokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenResponse)

	req, _ := http.NewRequest("GET", suite.server.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	client := &http.Client{}
	userInfoResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to get user info: %v", err)
	}
	defer userInfoResp.Body.Close()

	if userInfoResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userInfoResp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", userInfoResp.StatusCode, string(body))
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfo); err != nil {
		t.Fatalf("Failed to decode user info: %v", err)
	}

	if userInfo["username"] != "testuser" {
		t.Errorf("Expected username testuser, got %v", userInfo["username"])
	}

	if userInfo["email"] != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %v", userInfo["email"])
	}
}

func TestMetricsEndpoint(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	resp, err := http.Get(suite.server.URL + "/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	var metrics map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		t.Fatalf("Failed to decode metrics: %v", err)
	}

	if _, exists := metrics["oauth_metrics"]; !exists {
		t.Error("Expected oauth_metrics in response")
	}

	if _, exists := metrics["system_metrics"]; !exists {
		t.Error("Expected system_metrics in response")
	}
}

func TestErrorScenarios(t *testing.T) {
	suite := setupIntegrationTest()
	defer suite.cleanup()

	t.Run("Invalid client credentials", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", "invalid-client")
		data.Set("client_secret", "invalid-secret")

		resp, _ := http.PostForm(suite.server.URL+"/token", data)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}
	})

	t.Run("Invalid grant type", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", "invalid_grant")
		data.Set("client_id", "test-client")
		data.Set("client_secret", "test-secret")

		resp, _ := http.PostForm(suite.server.URL+"/token", data)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", resp.StatusCode)
		}
	})

	t.Run("Missing bearer token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", suite.server.URL+"/userinfo", nil)
		
		client := &http.Client{}
		resp, _ := client.Do(req)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}
	})

	t.Run("Expired authorization code", func(t *testing.T) {
		code := suite.createExpiredAuthorizationCode(t)
		
		data := url.Values{}
		data.Set("grant_type", "authorization_code")
		data.Set("code", code)
		data.Set("redirect_uri", "http://localhost:8080/callback")
		data.Set("client_id", "test-client")
		data.Set("client_secret", "test-secret")

		resp, _ := http.PostForm(suite.server.URL+"/token", data)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", resp.StatusCode)
		}
	})
}

func (suite *IntegrationTestSuite) createAuthorizationCode(t *testing.T) string {
	code, err := suite.authService.CreateAuthorizationCode(
		suite.mockDB.users["testuser"].ID,
		"test-client",
		"http://localhost:8080/callback",
		[]string{"openid", "profile", "email"},
		"",
		"",
	)
	if err != nil {
		t.Fatalf("Failed to create authorization code: %v", err)
	}
	return code
}

func (suite *IntegrationTestSuite) createAuthorizationCodeWithPKCE(t *testing.T, challenge, method string) string {
	code, err := suite.authService.CreateAuthorizationCode(
		suite.mockDB.users["testuser"].ID,
		"public-client",
		"http://localhost:8080/callback",
		[]string{"openid", "profile", "email"},
		challenge,
		method,
	)
	if err != nil {
		t.Fatalf("Failed to create PKCE authorization code: %v", err)
	}
	return code
}

func (suite *IntegrationTestSuite) createExpiredAuthorizationCode(t *testing.T) string {
	code, err := suite.jwtManager.GenerateAuthorizationCode()
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	authCode := &db.AuthorizationCode{
		Code:        code,
		ClientID:    "test-client",
		UserID:      suite.mockDB.users["testuser"].ID,
		RedirectURI: "http://localhost:8080/callback",
		Scopes:      []string{"openid", "profile"},
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // Expired
	}

	suite.mockDB.CreateAuthorizationCode(authCode)
	return code
}