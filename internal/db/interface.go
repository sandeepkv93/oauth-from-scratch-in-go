package db

import (
	"context"
	"github.com/google/uuid"
)

// Transactor interface for managing database transactions
type Transactor interface {
	BeginTx(ctx context.Context) (Transaction, error)
}

// Transaction interface for database transaction operations
type Transaction interface {
	DatabaseInterface
	Commit() error
	Rollback() error
}

type DatabaseInterface interface {
	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	
	// Client operations
	CreateClient(ctx context.Context, client *Client) error
	GetClientByID(ctx context.Context, clientID string) (*Client, error)
	GetAllClients(ctx context.Context) ([]*Client, error)
	
	// Dynamic Client Registration operations (RFC 7591)
	UpdateClient(ctx context.Context, client *Client) error
	DeleteClient(ctx context.Context, clientID string) error
	GetClientByRegistrationToken(ctx context.Context, token string) (*Client, error)
	
	// Authorization code operations
	CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	MarkAuthorizationCodeUsed(ctx context.Context, code string) error
	
	// Token operations
	CreateAccessToken(ctx context.Context, token *AccessToken) error
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	GetAccessToken(ctx context.Context, token string) (*AccessToken, error)
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	RevokeAccessToken(ctx context.Context, tokenID uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, token string) error
	
	// Device code operations
	CreateDeviceCode(ctx context.Context, deviceCode *DeviceCode) error
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	AuthorizeDeviceCode(ctx context.Context, userCode string, userID uuid.UUID) error
	
	// Scope operations
	CreateScope(ctx context.Context, scope *Scope) error
	GetScopeByName(ctx context.Context, name string) (*Scope, error)
	GetAllScopes(ctx context.Context) ([]*Scope, error)
	GetScopesByCategory(ctx context.Context, category string) ([]*Scope, error)
	UpdateScope(ctx context.Context, scope *Scope) error
	DeleteScope(ctx context.Context, name string) error
	GetDefaultScopes(ctx context.Context) ([]*Scope, error)
	
	// Scope consent operations
	CreateScopeConsent(ctx context.Context, consent *ScopeConsent) error
	GetScopeConsent(ctx context.Context, userID uuid.UUID, clientID, scope string) (*ScopeConsent, error)
	GetUserScopeConsents(ctx context.Context, userID uuid.UUID, clientID string) ([]*ScopeConsent, error)
	UpdateScopeConsent(ctx context.Context, consent *ScopeConsent) error
	RevokeScopeConsent(ctx context.Context, userID uuid.UUID, clientID, scope string) error
	CleanupExpiredConsents(ctx context.Context) error
	
	// Scope group operations
	CreateScopeGroup(ctx context.Context, group *ScopeGroup) error
	GetScopeGroup(ctx context.Context, id uuid.UUID) (*ScopeGroup, error)
	GetAllScopeGroups(ctx context.Context) ([]*ScopeGroup, error)
	UpdateScopeGroup(ctx context.Context, group *ScopeGroup) error
	DeleteScopeGroup(ctx context.Context, id uuid.UUID) error
	AddScopeToGroup(ctx context.Context, scopeID, groupID uuid.UUID) error
	RemoveScopeFromGroup(ctx context.Context, scopeID, groupID uuid.UUID) error
	GetScopesByGroup(ctx context.Context, groupID uuid.UUID) ([]*Scope, error)
	
	// Maintenance operations
	CleanupExpiredTokens(ctx context.Context) error
	CleanupExpiredCodes(ctx context.Context) error
	GetDatabaseStats(ctx context.Context) (*DatabaseStats, error)
	
	// Connection management
	Ping(ctx context.Context) error
	Close() error
}

// Database statistics for monitoring
type DatabaseStats struct {
	OpenConnections     int   `json:"open_connections"`
	InUse              int   `json:"in_use"`
	Idle               int   `json:"idle"`
	WaitCount          int64 `json:"wait_count"`
	WaitDuration       int64 `json:"wait_duration_ns"`
	MaxIdleClosed      int64 `json:"max_idle_closed"`
	MaxIdleTimeClosed  int64 `json:"max_idle_time_closed"`
	MaxLifetimeClosed  int64 `json:"max_lifetime_closed"`
}