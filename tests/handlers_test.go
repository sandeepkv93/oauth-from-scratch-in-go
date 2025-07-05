package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"oauth-server/internal/handlers"
)

func TestHandlerCreation(t *testing.T) {
	handler, _, _ := setupTestHandler()

	if handler == nil {
		t.Fatal("Handler should not be nil")
	}
}

func TestAuthorizeGetRequest(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile&state=xyz", nil)
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Authorize Application") {
		t.Error("Response should contain authorization page")
	}

	if !strings.Contains(body, "test-client") {
		t.Error("Response should contain client ID")
	}
}

func TestAuthorizeInvalidResponseType(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/authorize?response_type=token&client_id=test-client", nil)
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestAuthorizeInvalidClient(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=invalid-client", nil)
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestAuthorizeInvalidRedirectURI(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client&redirect_uri=http://evil.com/callback", nil)
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestAuthorizePostDeny(t *testing.T) {
	handler, _, _ := setupTestHandler()

	data := url.Values{}
	data.Set("action", "deny")
	data.Set("client_id", "test-client")
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("state", "xyz")

	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "error=access_denied") {
		t.Error("Redirect should contain access_denied error")
	}
}

func TestAuthorizePostInvalidCredentials(t *testing.T) {
	handler, _, _ := setupTestHandler()

	data := url.Values{}
	data.Set("action", "authorize")
	data.Set("client_id", "test-client")
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("username", "testuser")
	data.Set("password", "wrongpassword")
	data.Set("state", "xyz")

	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "error=access_denied") {
		t.Error("Redirect should contain access_denied error")
	}
}

func TestAuthorizePostSuccess(t *testing.T) {
	handler, _, _ := setupTestHandler()

	data := url.Values{}
	data.Set("action", "authorize")
	data.Set("client_id", "test-client")
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("scope", "openid profile")
	data.Set("username", "testuser")
	data.Set("password", "testpassword")
	data.Set("state", "xyz")

	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "code=") {
		t.Error("Redirect should contain authorization code")
	}

	if !strings.Contains(location, "state=xyz") {
		t.Error("Redirect should preserve state parameter")
	}
}

func TestTokenEndpointUnsupportedGrantType(t *testing.T) {
	handler, _, _ := setupTestHandler()

	data := url.Values{}
	data.Set("grant_type", "unsupported_grant")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var errorResponse map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&errorResponse); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResponse["error"] != "unsupported_grant_type" {
		t.Errorf("Expected error 'unsupported_grant_type', got %s", errorResponse["error"])
	}
}

func TestIntrospectMissingToken(t *testing.T) {
	handler, _, _ := setupTestHandler()

	data := url.Values{}

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Introspect(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestIntrospectInvalidToken(t *testing.T) {
	handler, _, _ := setupTestHandler()

	data := url.Values{}
	data.Set("token", "invalid-token")

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Introspect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["active"] != false {
		t.Error("Invalid token should be inactive")
	}
}

func TestUserInfoMissingToken(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/userinfo", nil)
	rr := httptest.NewRecorder()

	handler.UserInfo(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestUserInfoInvalidToken(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	handler.UserInfo(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestLoginGetRequest(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/login", nil)
	rr := httptest.NewRecorder()

	handler.Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Login") {
		t.Error("Response should contain login form")
	}
}

func TestLoginPostSuccess(t *testing.T) {
	handler, _, _ := setupTestHandler()

	data := url.Values{}
	data.Set("username", "testuser")
	data.Set("password", "testpassword")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["message"] != "Login successful" {
		t.Errorf("Expected success message, got %v", response["message"])
	}
}

func TestLoginPostInvalidCredentials(t *testing.T) {
	handler, _, _ := setupTestHandler()

	data := url.Values{}
	data.Set("username", "testuser")
	data.Set("password", "wrongpassword")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestCreateClient(t *testing.T) {
	handler, _, _ := setupTestHandler()

	clientData := map[string]interface{}{
		"name":          "Test Client App",
		"redirect_uris": []string{"http://localhost:3000/callback"},
		"scopes":        []string{"read", "write"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
		"is_public":     false,
	}

	jsonData, _ := json.Marshal(clientData)
	req := httptest.NewRequest("POST", "/api/clients", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.CreateClient(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["name"] != "Test Client App" {
		t.Errorf("Expected client name 'Test Client App', got %v", response["name"])
	}

	if response["client_id"] == "" {
		t.Error("Response should contain client_id")
	}

	if response["client_secret"] == "" {
		t.Error("Response should contain client_secret for confidential client")
	}
}

func TestCreatePublicClient(t *testing.T) {
	handler, _, _ := setupTestHandler()

	clientData := map[string]interface{}{
		"name":          "Public Client App",
		"redirect_uris": []string{"http://localhost:3000/callback"},
		"scopes":        []string{"read"},
		"grant_types":   []string{"authorization_code"},
		"is_public":     true,
	}

	jsonData, _ := json.Marshal(clientData)
	req := httptest.NewRequest("POST", "/api/clients", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.CreateClient(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["is_public"] != true {
		t.Error("Client should be public")
	}
}

func TestCreateClientInvalidJSON(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/clients", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.CreateClient(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestCreateUser(t *testing.T) {
	handler, _, _ := setupTestHandler()

	userData := map[string]interface{}{
		"username": "newuser",
		"email":    "newuser@example.com",
		"password": "password123",
		"scopes":   []string{"read", "write"},
	}

	jsonData, _ := json.Marshal(userData)
	req := httptest.NewRequest("POST", "/api/users", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.CreateUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["username"] != "newuser" {
		t.Errorf("Expected username 'newuser', got %v", response["username"])
	}

	if response["email"] != "newuser@example.com" {
		t.Errorf("Expected email 'newuser@example.com', got %v", response["email"])
	}

	if response["id"] == "" {
		t.Error("Response should contain user ID")
	}
}

func TestCreateUserInvalidJSON(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/users", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.CreateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestListClients(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/api/clients", nil)
	rr := httptest.NewRecorder()

	handler.ListClients(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response []map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(response) == 0 {
		t.Error("Response should contain at least placeholder data")
	}
}

func TestExtractBearerToken(t *testing.T) {
	handler, _, _ := setupTestHandler()

	testCases := []struct {
		authHeader   string
		expectEmpty  bool
	}{
		{"Bearer valid-token", false},
		{"Bearer ", true},
		{"Basic dGVzdDp0ZXN0", true},
		{"", true},
		{"Invalid header", true},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", "/userinfo", nil)
		if tc.authHeader != "" {
			req.Header.Set("Authorization", tc.authHeader)
		}
		rr := httptest.NewRecorder()

		handler.UserInfo(rr, req)

		if tc.expectEmpty {
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("Expected 401 for auth header '%s', got %d", tc.authHeader, rr.Code)
			}
		}
	}
}

func TestResponseContentTypes(t *testing.T) {
	handler, _, _ := setupTestHandler()

	endpoints := []struct {
		method   string
		path     string
		data     string
		expected string
	}{
		{"POST", "/token", "grant_type=client_credentials&client_id=invalid", "application/json"},
		{"POST", "/introspect", "token=invalid", "application/json"},
		{"GET", "/userinfo", "", "application/json"},
		{"POST", "/revoke", "token=invalid", "application/json"},
		{"POST", "/api/clients", "invalid json", "application/json"},
		{"POST", "/api/users", "invalid json", "application/json"},
		{"GET", "/api/clients", "", "application/json"},
	}

	for _, endpoint := range endpoints {
		req := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.data))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		switch endpoint.path {
		case "/token":
			handler.Token(rr, req)
		case "/introspect":
			handler.Introspect(rr, req)
		case "/userinfo":
			handler.UserInfo(rr, req)
		case "/revoke":
			handler.Revoke(rr, req)
		case "/api/clients":
			if endpoint.method == "POST" {
				req.Header.Set("Content-Type", "application/json")
				handler.CreateClient(rr, req)
			} else {
				handler.ListClients(rr, req)
			}
		case "/api/users":
			req.Header.Set("Content-Type", "application/json")
			handler.CreateUser(rr, req)
		}

		contentType := rr.Header().Get("Content-Type")
		if contentType != endpoint.expected {
			t.Errorf("Expected Content-Type %s for %s %s, got %s", 
				endpoint.expected, endpoint.method, endpoint.path, contentType)
		}
	}
}