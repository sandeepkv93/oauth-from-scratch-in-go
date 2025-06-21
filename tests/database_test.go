package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"oauth-server/internal/db"
)

func TestMockDatabaseCreation(t *testing.T) {
	mockDB := NewMockDatabase()
	if mockDB == nil {
		t.Fatal("Mock database should not be nil")
	}

	if mockDB.users == nil {
		t.Error("Users map should be initialized")
	}

	if mockDB.clients == nil {
		t.Error("Clients map should be initialized")
	}

	if mockDB.codes == nil {
		t.Error("Codes map should be initialized")
	}

	if mockDB.accessTokens == nil {
		t.Error("Access tokens map should be initialized")
	}

	if mockDB.refreshTokens == nil {
		t.Error("Refresh tokens map should be initialized")
	}
}

func TestMockCreateUser(t *testing.T) {
	mockDB := NewMockDatabase()

	user := &db.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "hashedpassword",
		Scopes:   []string{"read", "write"},
	}

	err := mockDB.CreateUser(user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if user.ID == uuid.Nil {
		t.Error("User ID should be set after creation")
	}

	if user.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set after creation")
	}

	if user.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set after creation")
	}

	storedUser := mockDB.users[user.Username]
	if storedUser == nil {
		t.Error("User should be stored in users map")
	}

	if storedUser.Username != user.Username {
		t.Errorf("Expected username %s, got %s", user.Username, storedUser.Username)
	}
}

func TestGetUserByUsername(t *testing.T) {
	mockDB := NewMockDatabase()

	originalUser := &db.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "hashedpassword",
		Scopes:   []string{"read"},
	}
	mockDB.CreateUser(originalUser)

	retrievedUser, err := mockDB.GetUserByUsername("testuser")
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if retrievedUser.Username != originalUser.Username {
		t.Errorf("Expected username %s, got %s", originalUser.Username, retrievedUser.Username)
	}

	if retrievedUser.Email != originalUser.Email {
		t.Errorf("Expected email %s, got %s", originalUser.Email, retrievedUser.Email)
	}

	_, err = mockDB.GetUserByUsername("nonexistent")
	if err == nil {
		t.Error("Should return error for nonexistent user")
	}
}

func TestGetUserByID(t *testing.T) {
	mockDB := NewMockDatabase()

	originalUser := &db.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "hashedpassword",
	}
	mockDB.CreateUser(originalUser)

	retrievedUser, err := mockDB.GetUserByID(originalUser.ID)
	if err != nil {
		t.Fatalf("Failed to get user by ID: %v", err)
	}

	if retrievedUser.ID != originalUser.ID {
		t.Errorf("Expected ID %s, got %s", originalUser.ID, retrievedUser.ID)
	}

	_, err = mockDB.GetUserByID(uuid.New())
	if err == nil {
		t.Error("Should return error for nonexistent user ID")
	}
}

func TestMockCreateClient(t *testing.T) {
	mockDB := NewMockDatabase()

	client := &db.Client{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Name:         "Test Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"authorization_code"},
		IsPublic:     false,
	}

	err := mockDB.CreateClient(client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client.ID == uuid.Nil {
		t.Error("Client ID should be set after creation")
	}

	if client.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set after creation")
	}

	storedClient := mockDB.clients[client.ClientID]
	if storedClient == nil {
		t.Error("Client should be stored in clients map")
	}
}

func TestGetClientByID(t *testing.T) {
	mockDB := NewMockDatabase()

	originalClient := &db.Client{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Name:         "Test Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}
	mockDB.CreateClient(originalClient)

	retrievedClient, err := mockDB.GetClientByID("test-client")
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	if retrievedClient.ClientID != originalClient.ClientID {
		t.Errorf("Expected client ID %s, got %s", originalClient.ClientID, retrievedClient.ClientID)
	}

	_, err = mockDB.GetClientByID("nonexistent")
	if err == nil {
		t.Error("Should return error for nonexistent client")
	}
}

func TestMockCreateAuthorizationCode(t *testing.T) {
	mockDB := NewMockDatabase()

	code := &db.AuthorizationCode{
		Code:        "test-code",
		ClientID:    "test-client",
		UserID:      uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"read"},
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	err := mockDB.CreateAuthorizationCode(code)
	if err != nil {
		t.Fatalf("Failed to create authorization code: %v", err)
	}

	if code.ID == uuid.Nil {
		t.Error("Code ID should be set after creation")
	}

	if code.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set after creation")
	}

	storedCode := mockDB.codes[code.Code]
	if storedCode == nil {
		t.Error("Code should be stored in codes map")
	}
}

func TestGetAuthorizationCode(t *testing.T) {
	mockDB := NewMockDatabase()

	originalCode := &db.AuthorizationCode{
		Code:        "test-code",
		ClientID:    "test-client",
		UserID:      uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"read"},
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	mockDB.CreateAuthorizationCode(originalCode)

	retrievedCode, err := mockDB.GetAuthorizationCode("test-code")
	if err != nil {
		t.Fatalf("Failed to get authorization code: %v", err)
	}

	if retrievedCode.Code != originalCode.Code {
		t.Errorf("Expected code %s, got %s", originalCode.Code, retrievedCode.Code)
	}

	_, err = mockDB.GetAuthorizationCode("nonexistent")
	if err == nil {
		t.Error("Should return error for nonexistent code")
	}
}

func TestGetExpiredAuthorizationCode(t *testing.T) {
	mockDB := NewMockDatabase()

	expiredCode := &db.AuthorizationCode{
		Code:        "expired-code",
		ClientID:    "test-client",
		UserID:      uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"read"},
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
		Used:        false,
	}
	mockDB.CreateAuthorizationCode(expiredCode)

	_, err := mockDB.GetAuthorizationCode("expired-code")
	if err == nil {
		t.Error("Should return error for expired code")
	}
}

func TestGetUsedAuthorizationCode(t *testing.T) {
	mockDB := NewMockDatabase()

	usedCode := &db.AuthorizationCode{
		Code:        "used-code",
		ClientID:    "test-client",
		UserID:      uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"read"},
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        true,
	}
	mockDB.CreateAuthorizationCode(usedCode)

	_, err := mockDB.GetAuthorizationCode("used-code")
	if err == nil {
		t.Error("Should return error for used code")
	}
}

func TestMarkAuthorizationCodeUsed(t *testing.T) {
	mockDB := NewMockDatabase()

	code := &db.AuthorizationCode{
		Code:        "test-code",
		ClientID:    "test-client",
		UserID:      uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"read"},
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	mockDB.CreateAuthorizationCode(code)

	err := mockDB.MarkAuthorizationCodeUsed("test-code")
	if err != nil {
		t.Fatalf("Failed to mark code as used: %v", err)
	}

	storedCode := mockDB.codes["test-code"]
	if !storedCode.Used {
		t.Error("Code should be marked as used")
	}

	err = mockDB.MarkAuthorizationCodeUsed("nonexistent")
	if err == nil {
		t.Error("Should return error for nonexistent code")
	}
}

func TestCreateAccessToken(t *testing.T) {
	mockDB := NewMockDatabase()

	token := &db.AccessToken{
		Token:     "test-access-token",
		ClientID:  "test-client",
		UserID:    uuid.New(),
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := mockDB.CreateAccessToken(token)
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	if token.ID == uuid.Nil {
		t.Error("Token ID should be set after creation")
	}

	if token.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set after creation")
	}

	storedToken := mockDB.accessTokens[token.Token]
	if storedToken == nil {
		t.Error("Token should be stored in access tokens map")
	}
}

func TestGetAccessToken(t *testing.T) {
	mockDB := NewMockDatabase()

	originalToken := &db.AccessToken{
		Token:     "test-access-token",
		ClientID:  "test-client",
		UserID:    uuid.New(),
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   false,
	}
	mockDB.CreateAccessToken(originalToken)

	retrievedToken, err := mockDB.GetAccessToken("test-access-token")
	if err != nil {
		t.Fatalf("Failed to get access token: %v", err)
	}

	if retrievedToken.Token != originalToken.Token {
		t.Errorf("Expected token %s, got %s", originalToken.Token, retrievedToken.Token)
	}

	_, err = mockDB.GetAccessToken("nonexistent")
	if err == nil {
		t.Error("Should return error for nonexistent token")
	}
}

func TestGetExpiredAccessToken(t *testing.T) {
	mockDB := NewMockDatabase()

	expiredToken := &db.AccessToken{
		Token:     "expired-token",
		ClientID:  "test-client",
		UserID:    uuid.New(),
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Revoked:   false,
	}
	mockDB.CreateAccessToken(expiredToken)

	_, err := mockDB.GetAccessToken("expired-token")
	if err == nil {
		t.Error("Should return error for expired token")
	}
}

func TestGetRevokedAccessToken(t *testing.T) {
	mockDB := NewMockDatabase()

	revokedToken := &db.AccessToken{
		Token:     "revoked-token",
		ClientID:  "test-client",
		UserID:    uuid.New(),
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   true,
	}
	mockDB.CreateAccessToken(revokedToken)

	_, err := mockDB.GetAccessToken("revoked-token")
	if err == nil {
		t.Error("Should return error for revoked token")
	}
}

func TestCreateRefreshToken(t *testing.T) {
	mockDB := NewMockDatabase()

	token := &db.RefreshToken{
		Token:         "test-refresh-token",
		AccessTokenID: uuid.New(),
		ClientID:      "test-client",
		UserID:        uuid.New(),
		Scopes:        []string{"read"},
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}

	err := mockDB.CreateRefreshToken(token)
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	if token.ID == uuid.Nil {
		t.Error("Token ID should be set after creation")
	}

	if token.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set after creation")
	}

	storedToken := mockDB.refreshTokens[token.Token]
	if storedToken == nil {
		t.Error("Token should be stored in refresh tokens map")
	}
}

func TestGetRefreshToken(t *testing.T) {
	mockDB := NewMockDatabase()

	originalToken := &db.RefreshToken{
		Token:         "test-refresh-token",
		AccessTokenID: uuid.New(),
		ClientID:      "test-client",
		UserID:        uuid.New(),
		Scopes:        []string{"read"},
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Revoked:       false,
	}
	mockDB.CreateRefreshToken(originalToken)

	retrievedToken, err := mockDB.GetRefreshToken("test-refresh-token")
	if err != nil {
		t.Fatalf("Failed to get refresh token: %v", err)
	}

	if retrievedToken.Token != originalToken.Token {
		t.Errorf("Expected token %s, got %s", originalToken.Token, retrievedToken.Token)
	}

	_, err = mockDB.GetRefreshToken("nonexistent")
	if err == nil {
		t.Error("Should return error for nonexistent token")
	}
}

func TestRevokeAccessToken(t *testing.T) {
	mockDB := NewMockDatabase()

	token := &db.AccessToken{
		Token:     "test-access-token",
		ClientID:  "test-client",
		UserID:    uuid.New(),
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   false,
	}
	mockDB.CreateAccessToken(token)

	err := mockDB.RevokeAccessToken(token.ID)
	if err != nil {
		t.Fatalf("Failed to revoke access token: %v", err)
	}

	storedToken := mockDB.accessTokens[token.Token]
	if !storedToken.Revoked {
		t.Error("Token should be marked as revoked")
	}

	err = mockDB.RevokeAccessToken(uuid.New())
	if err != nil {
		t.Error("Revoking nonexistent token should not return error")
	}
}

func TestMockRevokeRefreshToken(t *testing.T) {
	mockDB := NewMockDatabase()

	token := &db.RefreshToken{
		Token:         "test-refresh-token",
		AccessTokenID: uuid.New(),
		ClientID:      "test-client",
		UserID:        uuid.New(),
		Scopes:        []string{"read"},
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Revoked:       false,
	}
	mockDB.CreateRefreshToken(token)

	err := mockDB.RevokeRefreshToken("test-refresh-token")
	if err != nil {
		t.Fatalf("Failed to revoke refresh token: %v", err)
	}

	storedToken := mockDB.refreshTokens[token.Token]
	if !storedToken.Revoked {
		t.Error("Token should be marked as revoked")
	}

	err = mockDB.RevokeRefreshToken("nonexistent")
	if err != nil {
		t.Error("Revoking nonexistent token should not return error")
	}
}

func TestDatabaseClose(t *testing.T) {
	mockDB := NewMockDatabase()

	err := mockDB.Close()
	if err != nil {
		t.Errorf("Close should not return error: %v", err)
	}
}

func TestDatabaseInterface(t *testing.T) {
	var _ db.DatabaseInterface = &MockDB{}
}

func TestUserModel(t *testing.T) {
	user := &db.User{
		ID:        uuid.New(),
		Username:  "testuser",
		Email:     "test@example.com",
		Password:  "hashedpassword",
		Scopes:    []string{"read", "write"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if user.ID == uuid.Nil {
		t.Error("User ID should not be nil")
	}

	if user.Username == "" {
		t.Error("Username should not be empty")
	}

	if user.Email == "" {
		t.Error("Email should not be empty")
	}

	if len(user.Scopes) == 0 {
		t.Error("Scopes should not be empty")
	}
}

func TestClientModel(t *testing.T) {
	client := &db.Client{
		ID:           uuid.New(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Name:         "Test Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		IsPublic:     false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if client.ID == uuid.Nil {
		t.Error("Client ID should not be nil")
	}

	if client.ClientID == "" {
		t.Error("Client ID should not be empty")
	}

	if len(client.RedirectURIs) == 0 {
		t.Error("Redirect URIs should not be empty")
	}

	if len(client.Scopes) == 0 {
		t.Error("Scopes should not be empty")
	}

	if len(client.GrantTypes) == 0 {
		t.Error("Grant types should not be empty")
	}
}