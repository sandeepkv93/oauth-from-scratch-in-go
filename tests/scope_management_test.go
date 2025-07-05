package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"oauth-server/internal/db"
	"oauth-server/internal/scopes"
)

// Enhanced MockDB for scope testing
type ScopeMockDB struct {
	*MockDB
	scopes      map[string]*db.Scope
	consents    map[string]*db.ScopeConsent // key: userID-clientID-scope
	groups      map[uuid.UUID]*db.ScopeGroup
	memberships map[string]bool // key: scopeID-groupID
}

func NewScopeMockDB() *ScopeMockDB {
	return &ScopeMockDB{
		MockDB:      NewMockDatabase(),
		scopes:      make(map[string]*db.Scope),
		consents:    make(map[string]*db.ScopeConsent),
		groups:      make(map[uuid.UUID]*db.ScopeGroup),
		memberships: make(map[string]bool),
	}
}

// Override scope operations with actual implementations
func (m *ScopeMockDB) CreateScope(ctx context.Context, scope *db.Scope) error {
	m.scopes[scope.Name] = scope
	return nil
}

func (m *ScopeMockDB) GetScopeByName(ctx context.Context, name string) (*db.Scope, error) {
	if scope, exists := m.scopes[name]; exists {
		return scope, nil
	}
	return nil, scopes.ErrScopeNotFound
}

func (m *ScopeMockDB) GetAllScopes(ctx context.Context) ([]*db.Scope, error) {
	var allScopes []*db.Scope
	for _, scope := range m.scopes {
		allScopes = append(allScopes, scope)
	}
	return allScopes, nil
}

func (m *ScopeMockDB) GetScopesByCategory(ctx context.Context, category string) ([]*db.Scope, error) {
	var categoryScopes []*db.Scope
	for _, scope := range m.scopes {
		if scope.Category == category {
			categoryScopes = append(categoryScopes, scope)
		}
	}
	return categoryScopes, nil
}

func (m *ScopeMockDB) GetDefaultScopes(ctx context.Context) ([]*db.Scope, error) {
	var defaultScopes []*db.Scope
	for _, scope := range m.scopes {
		if scope.IsDefault {
			defaultScopes = append(defaultScopes, scope)
		}
	}
	return defaultScopes, nil
}

func (m *ScopeMockDB) CreateScopeConsent(ctx context.Context, consent *db.ScopeConsent) error {
	key := consent.UserID.String() + "-" + consent.ClientID + "-" + consent.Scope
	m.consents[key] = consent
	return nil
}

func (m *ScopeMockDB) GetScopeConsent(ctx context.Context, userID uuid.UUID, clientID, scope string) (*db.ScopeConsent, error) {
	key := userID.String() + "-" + clientID + "-" + scope
	if consent, exists := m.consents[key]; exists {
		return consent, nil
	}
	return nil, scopes.ErrScopeNotFound
}

func (m *ScopeMockDB) UpdateScopeConsent(ctx context.Context, consent *db.ScopeConsent) error {
	key := consent.UserID.String() + "-" + consent.ClientID + "-" + consent.Scope
	m.consents[key] = consent
	return nil
}

func TestScopeService_CreateScope(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Test creating a basic scope
	scope := &db.Scope{
		Name:        "test:read",
		Description: "Read access to test resources",
		Category:    "test",
		IsDefault:   true,
	}

	err := scopeService.CreateScope(ctx, scope)
	if err != nil {
		t.Errorf("Expected successful scope creation, got error: %v", err)
	}

	// Verify scope was created
	created, err := mockDB.GetScopeByName(ctx, "test:read")
	if err != nil {
		t.Errorf("Expected to find created scope, got error: %v", err)
	}
	if created.Name != "test:read" {
		t.Errorf("Expected scope name 'test:read', got '%s'", created.Name)
	}
}

func TestScopeService_CreateScopeWithParent(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Create parent scope first
	parentScope := &db.Scope{
		Name:        "admin",
		Description: "Administrative access",
		Category:    "admin",
	}
	err := scopeService.CreateScope(ctx, parentScope)
	if err != nil {
		t.Fatalf("Failed to create parent scope: %v", err)
	}

	// Create child scope
	parentName := "admin"
	childScope := &db.Scope{
		Name:        "admin:users",
		Description: "Administrative access to user management",
		Category:    "admin",
		ParentScope: &parentName,
	}

	err = scopeService.CreateScope(ctx, childScope)
	if err != nil {
		t.Errorf("Expected successful hierarchical scope creation, got error: %v", err)
	}
}

func TestScopeService_ValidateScopes(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Create test scopes
	testScopes := []*db.Scope{
		{Name: "read", Description: "Read access", Category: "data"},
		{Name: "write", Description: "Write access", Category: "data"},
		{Name: "admin", Description: "Admin access", Category: "admin"},
	}

	for _, scope := range testScopes {
		mockDB.CreateScope(ctx, scope)
	}

	// Test validation
	requestedScopes := []string{"read", "write", "invalid", "admin"}
	allowedScopes := []string{"read", "write", "profile"}

	result, err := scopeService.ValidateScopes(ctx, requestedScopes, allowedScopes)
	if err != nil {
		t.Errorf("Expected successful validation, got error: %v", err)
	}

	if len(result.Valid) != 2 {
		t.Errorf("Expected 2 valid scopes, got %d", len(result.Valid))
	}

	if len(result.Invalid) != 1 {
		t.Errorf("Expected 1 invalid scope, got %d", len(result.Invalid))
	}

	if len(result.Unauthorized) != 1 {
		t.Errorf("Expected 1 unauthorized scope, got %d", len(result.Unauthorized))
	}
}

func TestScopeService_ProcessConsentRequest(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Create test scopes with different consent requirements
	testScopes := []*db.Scope{
		{
			Name:            "openid",
			Description:     "OpenID Connect",
			Category:        "identity",
			RequiresConsent: false,
		},
		{
			Name:            "profile",
			Description:     "Profile information",
			Category:        "identity",
			RequiresConsent: true,
		},
	}

	for _, scope := range testScopes {
		mockDB.CreateScope(ctx, scope)
	}

	userID := uuid.New()
	clientID := "test-client"

	request := &scopes.ConsentRequest{
		UserID:   userID,
		ClientID: clientID,
		Scopes:   []string{"openid", "profile"},
	}

	response, err := scopeService.ProcessConsentRequest(ctx, request)
	if err != nil {
		t.Errorf("Expected successful consent processing, got error: %v", err)
	}

	// openid should be auto-granted (no consent required)
	if len(response.Granted) != 1 || response.Granted[0] != "openid" {
		t.Errorf("Expected openid to be auto-granted, got: %v", response.Granted)
	}

	// profile should require prompt
	if len(response.RequirePrompt) != 1 || response.RequirePrompt[0] != "profile" {
		t.Errorf("Expected profile to require prompt, got: %v", response.RequirePrompt)
	}
}

func TestScopeService_GrantConsent(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Create test scope
	scope := &db.Scope{
		Name:        "profile",
		Description: "Profile information",
		Category:    "identity",
	}
	mockDB.CreateScope(ctx, scope)

	userID := uuid.New()
	clientID := "test-client"
	scopes := []string{"profile"}

	// Grant consent
	err := scopeService.GrantConsent(ctx, userID, clientID, scopes, nil)
	if err != nil {
		t.Errorf("Expected successful consent grant, got error: %v", err)
	}

	// Verify consent was recorded
	consent, err := mockDB.GetScopeConsent(ctx, userID, clientID, "profile")
	if err != nil {
		t.Errorf("Expected to find consent record, got error: %v", err)
	}
	if !consent.Granted {
		t.Error("Expected consent to be granted")
	}
}

func TestScopeService_GrantConsentWithExpiration(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Create test scope
	scope := &db.Scope{
		Name:        "email",
		Description: "Email access",
		Category:    "identity",
	}
	mockDB.CreateScope(ctx, scope)

	userID := uuid.New()
	clientID := "test-client"
	scopes := []string{"email"}
	expiresIn := 3600 // 1 hour

	// Grant consent with expiration
	err := scopeService.GrantConsent(ctx, userID, clientID, scopes, &expiresIn)
	if err != nil {
		t.Errorf("Expected successful consent grant with expiration, got error: %v", err)
	}

	// Verify consent was recorded with expiration
	consent, err := mockDB.GetScopeConsent(ctx, userID, clientID, "email")
	if err != nil {
		t.Errorf("Expected to find consent record, got error: %v", err)
	}
	if consent.ExpiresAt == nil {
		t.Error("Expected consent to have expiration")
	}
	if consent.ExpiresAt.Before(time.Now()) {
		t.Error("Expected consent expiration to be in the future")
	}
}

func TestScopeService_GetScopeInfo(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Create parent and child scopes
	parentScope := &db.Scope{
		Name:        "admin",
		Description: "Administrative access",
		Category:    "admin",
	}
	mockDB.CreateScope(ctx, parentScope)

	parentName := "admin"
	childScope := &db.Scope{
		Name:        "admin:users",
		Description: "User administration",
		Category:    "admin",
		ParentScope: &parentName,
	}
	mockDB.CreateScope(ctx, childScope)

	// Get scope info for parent
	info, err := scopeService.GetScopeInfo(ctx, "admin")
	if err != nil {
		t.Errorf("Expected successful scope info retrieval, got error: %v", err)
	}

	if info.Name != "admin" {
		t.Errorf("Expected scope name 'admin', got '%s'", info.Name)
	}

	if len(info.Children) != 1 {
		t.Errorf("Expected 1 child scope, got %d", len(info.Children))
	}

	// Get scope info for child
	childInfo, err := scopeService.GetScopeInfo(ctx, "admin:users")
	if err != nil {
		t.Errorf("Expected successful child scope info retrieval, got error: %v", err)
	}

	if !childInfo.IsHierarchical {
		t.Error("Expected child scope to be marked as hierarchical")
	}

	if childInfo.ParentInfo == nil {
		t.Error("Expected child scope to have parent info")
	}
}

func TestScopeService_InitializeDefaultScopes(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Initialize default scopes
	err := scopeService.InitializeDefaultScopes(ctx)
	if err != nil {
		t.Errorf("Expected successful default scope initialization, got error: %v", err)
	}

	// Verify some standard scopes were created
	expectedScopes := []string{"openid", "profile", "email", "read", "write"}
	for _, scopeName := range expectedScopes {
		scope, err := mockDB.GetScopeByName(ctx, scopeName)
		if err != nil {
			t.Errorf("Expected to find default scope '%s', got error: %v", scopeName, err)
		}
		if scope == nil {
			t.Errorf("Expected default scope '%s' to exist", scopeName)
		}
	}

	// Verify default scopes are marked as default
	defaultScopes, err := mockDB.GetDefaultScopes(ctx)
	if err != nil {
		t.Errorf("Expected to retrieve default scopes, got error: %v", err)
	}
	if len(defaultScopes) == 0 {
		t.Error("Expected some default scopes to be marked as default")
	}
}

func TestScopeService_GetScopesByCategory(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Create scopes in different categories
	testScopes := []*db.Scope{
		{Name: "openid", Category: "identity", DisplayOrder: 1},
		{Name: "profile", Category: "identity", DisplayOrder: 2},
		{Name: "read", Category: "data", DisplayOrder: 1},
		{Name: "write", Category: "data", DisplayOrder: 2},
		{Name: "admin", Category: "admin", DisplayOrder: 1},
	}

	for _, scope := range testScopes {
		mockDB.CreateScope(ctx, scope)
	}

	// Get scopes by category
	categories, err := scopeService.GetScopesByCategory(ctx)
	if err != nil {
		t.Errorf("Expected successful category retrieval, got error: %v", err)
	}

	if len(categories) != 3 {
		t.Errorf("Expected 3 categories, got %d", len(categories))
	}

	// Check identity category
	identityScopes := categories["identity"]
	if len(identityScopes) != 2 {
		t.Errorf("Expected 2 identity scopes, got %d", len(identityScopes))
	}

	// Check data category
	dataScopes := categories["data"]
	if len(dataScopes) != 2 {
		t.Errorf("Expected 2 data scopes, got %d", len(dataScopes))
	}
}

func TestScopeService_CircularDependencyDetection(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Test 1: Direct self-reference
	selfRef := "self-ref"
	selfRefScope := &db.Scope{
		Name:        "self-ref",
		Description: "Self-referencing scope",
		Category:    "test",
		ParentScope: &selfRef, // Self-reference
	}

	err := scopeService.CreateScope(ctx, selfRefScope)
	if err == nil {
		t.Error("Expected error for self-referencing scope")
	}

	// Test 2: Create a chain that would create circular dependency
	// Create A -> B -> C, then try to make C -> A
	scopeA := &db.Scope{
		Name:        "scope-a",
		Description: "Scope A",
		Category:    "test",
	}
	err = scopeService.CreateScope(ctx, scopeA)
	if err != nil {
		t.Fatalf("Failed to create scope A: %v", err)
	}

	parentA := "scope-a"
	scopeB := &db.Scope{
		Name:        "scope-b",
		Description: "Scope B",
		Category:    "test",
		ParentScope: &parentA,
	}
	err = scopeService.CreateScope(ctx, scopeB)
	if err != nil {
		t.Fatalf("Failed to create scope B: %v", err)
	}

	parentB := "scope-b"
	scopeC := &db.Scope{
		Name:        "scope-c",
		Description: "Scope C",
		Category:    "test",
		ParentScope: &parentB,
	}
	err = scopeService.CreateScope(ctx, scopeC)
	if err != nil {
		t.Fatalf("Failed to create scope C: %v", err)
	}

	// Now try to make A depend on C (which would create a cycle)
	scopeA.ParentScope = &scopeC.Name
	// This should be detected as circular dependency in a real update operation
	// For now, we just test the direct self-reference case
}

func TestScopeService_InvalidScopeName(t *testing.T) {
	mockDB := NewScopeMockDB()
	scopeService := scopes.NewService(mockDB)
	ctx := context.Background()

	// Test empty name
	scope := &db.Scope{
		Name:        "",
		Description: "Invalid scope",
		Category:    "test",
	}

	err := scopeService.CreateScope(ctx, scope)
	if err == nil {
		t.Error("Expected error for empty scope name")
	}

	// Test name with whitespace
	scope.Name = "invalid scope"
	err = scopeService.CreateScope(ctx, scope)
	if err == nil {
		t.Error("Expected error for scope name with whitespace")
	}
}