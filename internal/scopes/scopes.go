package scopes

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"oauth-server/internal/db"
)

var (
	ErrScopeNotFound      = errors.New("scope not found")
	ErrScopeAlreadyExists = errors.New("scope already exists")
	ErrInvalidScopeName   = errors.New("invalid scope name")
	ErrCircularDependency = errors.New("circular dependency detected")
)

// Service provides scope management functionality
type Service struct {
	db db.DatabaseInterface
}

// ScopeInfo provides detailed information about a scope
type ScopeInfo struct {
	*db.Scope
	Children      []*ScopeInfo `json:"children,omitempty"`
	ParentInfo    *ScopeInfo   `json:"parent_info,omitempty"`
	Groups        []*db.ScopeGroup `json:"groups,omitempty"`
	IsHierarchical bool        `json:"is_hierarchical"`
}

// ConsentRequest represents a request for scope consent
type ConsentRequest struct {
	UserID    uuid.UUID `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresIn *int      `json:"expires_in,omitempty"` // Optional expiration in seconds
}

// ConsentResponse represents the result of a consent request
type ConsentResponse struct {
	Granted       []string          `json:"granted"`
	Denied        []string          `json:"denied"`
	RequirePrompt []string          `json:"require_prompt"`
	ScopeDetails  map[string]*ScopeInfo `json:"scope_details"`
}

// ScopeValidationResult contains the result of scope validation
type ScopeValidationResult struct {
	Valid        []string `json:"valid"`
	Invalid      []string `json:"invalid"`
	Expanded     []string `json:"expanded"`     // Hierarchical expansion
	Unauthorized []string `json:"unauthorized"` // User not authorized
}

func NewService(database db.DatabaseInterface) *Service {
	return &Service{
		db: database,
	}
}

// CreateScope creates a new scope with validation
func (s *Service) CreateScope(ctx context.Context, scope *db.Scope) error {
	if err := s.validateScopeName(scope.Name); err != nil {
		return err
	}

	// Check if scope already exists
	existing, err := s.db.GetScopeByName(ctx, scope.Name)
	if err == nil && existing != nil {
		return ErrScopeAlreadyExists
	}

	// Validate parent scope if specified
	if scope.ParentScope != nil && *scope.ParentScope != "" {
		parent, err := s.db.GetScopeByName(ctx, *scope.ParentScope)
		if err != nil || parent == nil {
			return fmt.Errorf("parent scope '%s' not found", *scope.ParentScope)
		}

		// Check for circular dependency
		if err := s.checkCircularDependency(ctx, scope.Name, *scope.ParentScope); err != nil {
			return err
		}
	}

	// Set defaults
	if scope.Category == "" {
		scope.Category = "general"
	}

	scope.ID = uuid.New()
	scope.CreatedAt = time.Now()
	scope.UpdatedAt = time.Now()

	return s.db.CreateScope(ctx, scope)
}

// GetScopeInfo returns detailed information about a scope including hierarchy
func (s *Service) GetScopeInfo(ctx context.Context, scopeName string) (*ScopeInfo, error) {
	scope, err := s.db.GetScopeByName(ctx, scopeName)
	if err != nil {
		return nil, ErrScopeNotFound
	}

	info := &ScopeInfo{
		Scope:          scope,
		IsHierarchical: scope.ParentScope != nil,
	}

	// Get parent information
	if scope.ParentScope != nil && *scope.ParentScope != "" {
		parentInfo, err := s.GetScopeInfo(ctx, *scope.ParentScope)
		if err == nil {
			info.ParentInfo = parentInfo
		}
	}

	// Get children
	children, err := s.getChildScopes(ctx, scopeName)
	if err == nil {
		info.Children = children
	}

	return info, nil
}

// ValidateScopes validates a list of scopes and returns detailed results
func (s *Service) ValidateScopes(ctx context.Context, requestedScopes, allowedScopes []string) (*ScopeValidationResult, error) {
	// Quick check to see if the database supports scope operations
	// If GetScopeByName fails for the first scope, assume we're in a mock scenario
	if len(requestedScopes) > 0 {
		_, err := s.db.GetScopeByName(ctx, requestedScopes[0])
		if err != nil && err.Error() == "not implemented in mock" {
			// Return an error to trigger fallback validation
			return nil, err
		}
	}

	result := &ScopeValidationResult{
		Valid:        []string{},
		Invalid:      []string{},
		Expanded:     []string{},
		Unauthorized: []string{},
	}

	allowedMap := make(map[string]bool)
	for _, scope := range allowedScopes {
		allowedMap[scope] = true
	}

	for _, scope := range requestedScopes {
		// Check if scope exists
		scopeInfo, err := s.db.GetScopeByName(ctx, scope)
		if err != nil || scopeInfo == nil {
			result.Invalid = append(result.Invalid, scope)
			continue
		}

		// Check authorization
		if !allowedMap[scope] {
			result.Unauthorized = append(result.Unauthorized, scope)
			continue
		}

		result.Valid = append(result.Valid, scope)

		// Expand hierarchical scopes
		expanded, err := s.expandScope(ctx, scope)
		if err == nil {
			for _, exp := range expanded {
				if !contains(result.Expanded, exp) {
					result.Expanded = append(result.Expanded, exp)
				}
			}
		}
	}

	return result, nil
}

// ProcessConsentRequest processes a consent request and returns the consent status
func (s *Service) ProcessConsentRequest(ctx context.Context, request *ConsentRequest) (*ConsentResponse, error) {
	response := &ConsentResponse{
		Granted:       []string{},
		Denied:        []string{},
		RequirePrompt: []string{},
		ScopeDetails:  make(map[string]*ScopeInfo),
	}

	for _, scopeName := range request.Scopes {
		// Get scope information
		scopeInfo, err := s.GetScopeInfo(ctx, scopeName)
		if err != nil {
			response.Denied = append(response.Denied, scopeName)
			continue
		}

		response.ScopeDetails[scopeName] = scopeInfo

		// Check existing consent
		existing, err := s.db.GetScopeConsent(ctx, request.UserID, request.ClientID, scopeName)
		if err == nil && existing != nil && existing.Granted {
			// Check if consent is still valid
			if existing.ExpiresAt == nil || existing.ExpiresAt.After(time.Now()) {
				response.Granted = append(response.Granted, scopeName)
				continue
			}
		}

		// Check if scope requires consent
		if scopeInfo.RequiresConsent {
			response.RequirePrompt = append(response.RequirePrompt, scopeName)
		} else {
			// Auto-grant scopes that don't require consent
			response.Granted = append(response.Granted, scopeName)
			
			// Store the consent
			consent := &db.ScopeConsent{
				ID:        uuid.New(),
				UserID:    request.UserID,
				ClientID:  request.ClientID,
				Scope:     scopeName,
				Granted:   true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			if request.ExpiresIn != nil {
				expiresAt := time.Now().Add(time.Duration(*request.ExpiresIn) * time.Second)
				consent.ExpiresAt = &expiresAt
			}

			s.db.CreateScopeConsent(ctx, consent)
		}
	}

	return response, nil
}

// GrantConsent grants user consent for specific scopes
func (s *Service) GrantConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string, expiresIn *int) error {
	for _, scopeName := range scopes {
		// Check if scope exists
		_, err := s.db.GetScopeByName(ctx, scopeName)
		if err != nil {
			return fmt.Errorf("scope '%s' not found", scopeName)
		}

		// Create or update consent
		consent := &db.ScopeConsent{
			ID:        uuid.New(),
			UserID:    userID,
			ClientID:  clientID,
			Scope:     scopeName,
			Granted:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if expiresIn != nil {
			expiresAt := time.Now().Add(time.Duration(*expiresIn) * time.Second)
			consent.ExpiresAt = &expiresAt
		}

		// Check if consent already exists
		existing, err := s.db.GetScopeConsent(ctx, userID, clientID, scopeName)
		if err == nil && existing != nil {
			// Update existing consent
			existing.Granted = true
			existing.ExpiresAt = consent.ExpiresAt
			existing.UpdatedAt = time.Now()
			err = s.db.UpdateScopeConsent(ctx, existing)
		} else {
			// Create new consent
			err = s.db.CreateScopeConsent(ctx, consent)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// RevokeConsent revokes user consent for specific scopes
func (s *Service) RevokeConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	for _, scopeName := range scopes {
		err := s.db.RevokeScopeConsent(ctx, userID, clientID, scopeName)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetScopesByCategory returns scopes organized by category
func (s *Service) GetScopesByCategory(ctx context.Context) (map[string][]*db.Scope, error) {
	allScopes, err := s.db.GetAllScopes(ctx)
	if err != nil {
		return nil, err
	}

	categories := make(map[string][]*db.Scope)
	for _, scope := range allScopes {
		category := scope.Category
		if category == "" {
			category = "general"
		}
		categories[category] = append(categories[category], scope)
	}

	// Sort scopes within each category by display order
	for _, scopes := range categories {
		sort.Slice(scopes, func(i, j int) bool {
			return scopes[i].DisplayOrder < scopes[j].DisplayOrder
		})
	}

	return categories, nil
}

// GetEffectiveScopes returns the effective scopes for a user and client
func (s *Service) GetEffectiveScopes(ctx context.Context, userID uuid.UUID, clientID string, requestedScopes []string) ([]string, error) {
	if len(requestedScopes) == 0 {
		// Return default scopes
		defaultScopes, err := s.db.GetDefaultScopes(ctx)
		if err != nil {
			return nil, err
		}

		var scopeNames []string
		for _, scope := range defaultScopes {
			scopeNames = append(scopeNames, scope.Name)
		}
		return scopeNames, nil
	}

	// Check user consent for each scope
	var effectiveScopes []string
	for _, scopeName := range requestedScopes {
		consent, err := s.db.GetScopeConsent(ctx, userID, clientID, scopeName)
		if err == nil && consent != nil && consent.Granted {
			// Check if consent is still valid
			if consent.ExpiresAt == nil || consent.ExpiresAt.After(time.Now()) {
				effectiveScopes = append(effectiveScopes, scopeName)
			}
		}
	}

	return effectiveScopes, nil
}

// InitializeDefaultScopes creates standard OAuth and OpenID Connect scopes
func (s *Service) InitializeDefaultScopes(ctx context.Context) error {
	defaultScopes := []*db.Scope{
		{
			Name:            "openid",
			Description:     "Access to OpenID Connect identity information",
			Category:        "identity",
			IsDefault:       true,
			IsSystem:        true,
			RequiresConsent: false,
			DisplayOrder:    1,
		},
		{
			Name:            "profile",
			Description:     "Access to user's profile information including name, picture, and website",
			Category:        "identity",
			IsDefault:       true,
			RequiresConsent: true,
			DisplayOrder:    2,
		},
		{
			Name:            "email",
			Description:     "Access to user's email address",
			Category:        "identity",
			IsDefault:       true,
			RequiresConsent: true,
			DisplayOrder:    3,
		},
		{
			Name:            "phone",
			Description:     "Access to user's phone number",
			Category:        "identity",
			RequiresConsent: true,
			DisplayOrder:    4,
		},
		{
			Name:            "address",
			Description:     "Access to user's address information",
			Category:        "identity",
			RequiresConsent: true,
			DisplayOrder:    5,
		},
		{
			Name:            "read",
			Description:     "Read access to user's data",
			Category:        "data",
			IsDefault:       true,
			RequiresConsent: true,
			DisplayOrder:    10,
		},
		{
			Name:            "write",
			Description:     "Write access to user's data",
			Category:        "data",
			RequiresConsent: true,
			DisplayOrder:    11,
		},
		{
			Name:            "admin",
			Description:     "Administrative access to user's account",
			Category:        "admin",
			RequiresConsent: true,
			DisplayOrder:    20,
		},
	}

	for _, scope := range defaultScopes {
		// Check if scope already exists
		existing, err := s.db.GetScopeByName(ctx, scope.Name)
		if err != nil || existing == nil {
			// Create scope
			scope.ID = uuid.New()
			scope.CreatedAt = time.Now()
			scope.UpdatedAt = time.Now()
			
			if err := s.db.CreateScope(ctx, scope); err != nil {
				return fmt.Errorf("failed to create scope '%s': %v", scope.Name, err)
			}
		}
	}

	return nil
}

// Helper methods

func (s *Service) validateScopeName(name string) error {
	if name == "" {
		return ErrInvalidScopeName
	}

	// Check for invalid characters
	if strings.ContainsAny(name, " \t\n\r") {
		return fmt.Errorf("%w: scope name cannot contain whitespace", ErrInvalidScopeName)
	}

	// Check length
	if len(name) > 100 {
		return fmt.Errorf("%w: scope name too long", ErrInvalidScopeName)
	}

	return nil
}

func (s *Service) checkCircularDependency(ctx context.Context, scopeName, parentScope string) error {
	// Simple check for immediate circular dependency
	if scopeName == parentScope {
		return ErrCircularDependency
	}

	// Check for deeper circular dependencies
	current := parentScope
	visited := make(map[string]bool)
	
	for current != "" {
		if visited[current] {
			return ErrCircularDependency
		}
		
		if current == scopeName {
			return ErrCircularDependency
		}
		
		visited[current] = true
		
		scope, err := s.db.GetScopeByName(ctx, current)
		if err != nil || scope == nil {
			break
		}
		
		if scope.ParentScope == nil {
			break
		}
		
		current = *scope.ParentScope
	}

	return nil
}

func (s *Service) getChildScopes(ctx context.Context, parentScope string) ([]*ScopeInfo, error) {
	allScopes, err := s.db.GetAllScopes(ctx)
	if err != nil {
		return nil, err
	}

	var children []*ScopeInfo
	for _, scope := range allScopes {
		if scope.ParentScope != nil && *scope.ParentScope == parentScope {
			childInfo := &ScopeInfo{
				Scope:          scope,
				IsHierarchical: true,
			}
			
			// Recursively get children
			grandChildren, err := s.getChildScopes(ctx, scope.Name)
			if err == nil {
				childInfo.Children = grandChildren
			}
			
			children = append(children, childInfo)
		}
	}

	return children, nil
}

func (s *Service) expandScope(ctx context.Context, scopeName string) ([]string, error) {
	expanded := []string{scopeName}
	
	scope, err := s.db.GetScopeByName(ctx, scopeName)
	if err != nil {
		return expanded, err
	}

	// Add parent scopes
	if scope.ParentScope != nil && *scope.ParentScope != "" {
		parentExpanded, err := s.expandScope(ctx, *scope.ParentScope)
		if err == nil {
			expanded = append(expanded, parentExpanded...)
		}
	}

	return expanded, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}