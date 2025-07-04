package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/auth"
	"oauth-server/internal/config"
	"oauth-server/internal/db"
	"oauth-server/pkg/jwt"
)

// Mock database for testing
type MockDB struct {
	users  map[string]*db.User
	clients map[string]*db.Client
	codes   map[string]*db.AuthorizationCode
	accessTokens map[string]*db.AccessToken
	refreshTokens map[string]*db.RefreshToken
	deviceCodes map[string]*db.DeviceCode
}

func NewMockDatabase() *MockDB {
	return &MockDB{
		users:         make(map[string]*db.User),
		clients:       make(map[string]*db.Client),
		codes:         make(map[string]*db.AuthorizationCode),
		accessTokens:  make(map[string]*db.AccessToken),
		refreshTokens: make(map[string]*db.RefreshToken),
		deviceCodes:   make(map[string]*db.DeviceCode),
	}
}

func (m *MockDB) CreateUser(user *db.User) error {
	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.Username] = user
	return nil
}

func (m *MockDB) GetUserByUsername(username string) (*db.User, error) {
	if user, exists := m.users[username]; exists {
		return user, nil
	}
	return nil, auth.ErrInvalidCredentials
}

func (m *MockDB) GetUserByID(id uuid.UUID) (*db.User, error) {
	for _, user := range m.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, auth.ErrInvalidCredentials
}

func (m *MockDB) CreateClient(client *db.Client) error {
	client.ID = uuid.New()
	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()
	m.clients[client.ClientID] = client
	return nil
}

func (m *MockDB) GetClientByID(clientID string) (*db.Client, error) {
	if client, exists := m.clients[clientID]; exists {
		return client, nil
	}
	return nil, auth.ErrInvalidClient
}

func (m *MockDB) GetAllClients() ([]*db.Client, error) {
	clients := make([]*db.Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	return clients, nil
}

func (m *MockDB) CreateAuthorizationCode(code *db.AuthorizationCode) error {
	code.ID = uuid.New()
	code.CreatedAt = time.Now()
	m.codes[code.Code] = code
	return nil
}

func (m *MockDB) GetAuthorizationCode(code string) (*db.AuthorizationCode, error) {
	if authCode, exists := m.codes[code]; exists && !authCode.Used && authCode.ExpiresAt.After(time.Now()) {
		return authCode, nil
	}
	return nil, auth.ErrExpiredCode
}

func (m *MockDB) MarkAuthorizationCodeUsed(code string) error {
	if authCode, exists := m.codes[code]; exists {
		authCode.Used = true
		return nil
	}
	return auth.ErrExpiredCode
}

func (m *MockDB) CreateAccessToken(token *db.AccessToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	m.accessTokens[token.Token] = token
	return nil
}

func (m *MockDB) CreateRefreshToken(token *db.RefreshToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	m.refreshTokens[token.Token] = token
	return nil
}

func (m *MockDB) GetAccessToken(token string) (*db.AccessToken, error) {
	if accessToken, exists := m.accessTokens[token]; exists && !accessToken.Revoked && accessToken.ExpiresAt.After(time.Now()) {
		return accessToken, nil
	}
	return nil, auth.ErrInvalidCredentials
}

func (m *MockDB) GetRefreshToken(token string) (*db.RefreshToken, error) {
	if refreshToken, exists := m.refreshTokens[token]; exists && !refreshToken.Revoked && refreshToken.ExpiresAt.After(time.Now()) {
		return refreshToken, nil
	}
	return nil, auth.ErrInvalidCredentials
}

func (m *MockDB) RevokeAccessToken(tokenID uuid.UUID) error {
	for _, token := range m.accessTokens {
		if token.ID == tokenID {
			token.Revoked = true
			return nil
		}
	}
	return nil
}

func (m *MockDB) RevokeRefreshToken(token string) error {
	if refreshToken, exists := m.refreshTokens[token]; exists {
		refreshToken.Revoked = true
		return nil
	}
	return nil
}

func (m *MockDB) CreateDeviceCode(deviceCode *db.DeviceCode) error {
	deviceCode.ID = uuid.New()
	deviceCode.CreatedAt = time.Now()
	m.deviceCodes[deviceCode.DeviceCode] = deviceCode
	return nil
}

func (m *MockDB) GetDeviceCode(deviceCode string) (*db.DeviceCode, error) {
	if device, exists := m.deviceCodes[deviceCode]; exists && device.ExpiresAt.After(time.Now()) {
		return device, nil
	}
	return nil, auth.ErrExpiredToken
}

func (m *MockDB) GetDeviceCodeByUserCode(userCode string) (*db.DeviceCode, error) {
	for _, device := range m.deviceCodes {
		if device.UserCode == userCode && device.ExpiresAt.After(time.Now()) {
			return device, nil
		}
	}
	return nil, auth.ErrExpiredToken
}

func (m *MockDB) AuthorizeDeviceCode(userCode string, userID uuid.UUID) error {
	for _, device := range m.deviceCodes {
		if device.UserCode == userCode && device.ExpiresAt.After(time.Now()) {
			device.Authorized = true
			device.UserID = &userID
			return nil
		}
	}
	return auth.ErrExpiredToken
}

func (m *MockDB) Close() error {
	return nil
}

func setupTestAuth() (*auth.Service, *MockDB) {
	mockDatabase := NewMockDatabase()
	
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:            "test-secret",
			AccessTokenTTL:       15 * time.Minute,
			RefreshTokenTTL:      7 * 24 * time.Hour,
			AuthorizationCodeTTL: 10 * time.Minute,
		},
		Security: config.SecurityConfig{
			MinPasswordLength: 8,
		},
	}

	jwtManager := jwt.NewManager(cfg.Auth.JWTSecret)
	authService := auth.NewService(mockDatabase, jwtManager, cfg)

	// Create test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	testUser := &db.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Scopes:   []string{"openid", "profile", "email", "read"},
	}
	mockDatabase.CreateUser(testUser)

	// Create test client
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	testClient := &db.Client{
		ClientID:     "test-client",
		ClientSecret: string(hashedSecret),
		Name:         "Test Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"openid", "profile", "email", "read", "write"},
		GrantTypes:   []string{"authorization_code", "refresh_token", "client_credentials"},
		IsPublic:     false,
	}
	mockDatabase.CreateClient(testClient)

	return authService, mockDatabase
}

func TestAuthenticateUser(t *testing.T) {
	authService, _ := setupTestAuth()

	user, err := authService.AuthenticateUser("testuser", "testpassword")
	if err != nil {
		t.Errorf("Expected successful authentication, got error: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	_, err = authService.AuthenticateUser("testuser", "wrongpassword")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestValidateClient(t *testing.T) {
	authService, _ := setupTestAuth()

	client, err := authService.ValidateClient("test-client", "test-secret")
	if err != nil {
		t.Errorf("Expected successful client validation, got error: %v", err)
	}
	if client.ClientID != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%s'", client.ClientID)
	}

	_, err = authService.ValidateClient("test-client", "wrong-secret")
	if err != auth.ErrInvalidClient {
		t.Errorf("Expected ErrInvalidClient, got: %v", err)
	}

	_, err = authService.ValidateClient("invalid-client", "test-secret")
	if err != auth.ErrInvalidClient {
		t.Errorf("Expected ErrInvalidClient, got: %v", err)
	}
}

func TestCreateAuthorizationCode(t *testing.T) {
	authService, mockDb := setupTestAuth()

	userID := uuid.New()
	for _, user := range mockDb.users {
		userID = user.ID
		break
	}

	code, err := authService.CreateAuthorizationCode(
		userID,
		"test-client",
		"http://localhost:8080/callback",
		[]string{"openid", "profile"},
		"",
		"",
	)

	if err != nil {
		t.Errorf("Expected successful code creation, got error: %v", err)
	}
	if code == "" {
		t.Error("Expected non-empty authorization code")
	}

	authCode, exists := mockDb.codes[code]
	if !exists {
		t.Error("Authorization code not found in database")
	}
	if authCode.ClientID != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%s'", authCode.ClientID)
	}
}

func TestClientCredentialsGrant(t *testing.T) {
	authService, _ := setupTestAuth()

	req := &auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scope:        "read write",
	}

	response, err := authService.ClientCredentialsGrant(req)
	if err != nil {
		t.Errorf("Expected successful client credentials grant, got error: %v", err)
	}
	if response.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}
	if response.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", response.TokenType)
	}
}

func TestValidateScopes(t *testing.T) {
	authService, _ := setupTestAuth()

	allowedScopes := []string{"openid", "profile", "email", "read"}

	err := authService.ValidateScopes([]string{"openid", "profile"}, allowedScopes)
	if err != nil {
		t.Errorf("Expected valid scopes, got error: %v", err)
	}

	err = authService.ValidateScopes([]string{"openid", "admin"}, allowedScopes)
	if err != auth.ErrInvalidScope {
		t.Errorf("Expected ErrInvalidScope, got: %v", err)
	}
}

func TestJWTTokenGeneration(t *testing.T) {
	jwtManager := jwt.NewManager("test-secret")

	userID := uuid.New()
	clientID := "test-client"
	scopes := []string{"openid", "profile"}
	tokenID := uuid.New()
	ttl := 15 * time.Minute

	token, err := jwtManager.GenerateAccessToken(userID, clientID, scopes, tokenID, ttl)
	if err != nil {
		t.Errorf("Expected successful token generation, got error: %v", err)
	}
	if token == "" {
		t.Error("Expected non-empty token")
	}

	claims, err := jwtManager.ValidateAccessToken(token)
	if err != nil {
		t.Errorf("Expected successful token validation, got error: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("Expected user_id '%s', got '%s'", userID, claims.UserID)
	}
	if claims.ClientID != clientID {
		t.Errorf("Expected client_id '%s', got '%s'", clientID, claims.ClientID)
	}
}