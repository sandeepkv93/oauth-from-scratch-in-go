package db

import (
	"time"

	"github.com/google/uuid"
)

type Client struct {
	ID           uuid.UUID `json:"id" db:"id"`
	ClientID     string    `json:"client_id" db:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty" db:"client_secret"` // Deprecated: use ClientSecrets table
	Name         string    `json:"name" db:"name"`
	RedirectURIs []string  `json:"redirect_uris" db:"redirect_uris"`
	Scopes       []string  `json:"scopes" db:"scopes"`
	GrantTypes   []string  `json:"grant_types" db:"grant_types"`
	IsPublic     bool      `json:"is_public" db:"is_public"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`

	// Dynamic Client Registration fields (RFC 7591)
	ClientName              *string    `json:"client_name,omitempty" db:"client_name"`
	ClientURI               *string    `json:"client_uri,omitempty" db:"client_uri"`
	LogoURI                 *string    `json:"logo_uri,omitempty" db:"logo_uri"`
	ContactEmails           []string   `json:"contacts,omitempty" db:"contacts"`
	TosURI                  *string    `json:"tos_uri,omitempty" db:"tos_uri"`
	PolicyURI               *string    `json:"policy_uri,omitempty" db:"policy_uri"`
	JwksURI                 *string    `json:"jwks_uri,omitempty" db:"jwks_uri"`
	Jwks                    *string    `json:"jwks,omitempty" db:"jwks"`
	SoftwareID              *string    `json:"software_id,omitempty" db:"software_id"`
	SoftwareVersion         *string    `json:"software_version,omitempty" db:"software_version"`
	TokenEndpointAuthMethod *string    `json:"token_endpoint_auth_method,omitempty" db:"token_endpoint_auth_method"`
	ResponseTypes           []string   `json:"response_types,omitempty" db:"response_types"`
	ClientSecretExpiresAt   *time.Time `json:"client_secret_expires_at,omitempty" db:"client_secret_expires_at"`
	RegistrationAccessToken *string    `json:"registration_access_token,omitempty" db:"registration_access_token"`
	RegistrationClientURI   *string    `json:"registration_client_uri,omitempty" db:"registration_client_uri"`
	ClientIDIssuedAt        *time.Time `json:"client_id_issued_at,omitempty" db:"client_id_issued_at"`
}

// ClientSecret represents a client secret with rotation support
type ClientSecret struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	ClientID   uuid.UUID  `json:"client_id" db:"client_id"`      // References clients.id
	SecretHash string     `json:"-" db:"secret_hash"`             // bcrypt hash, never exposed
	PlainText  string     `json:"client_secret,omitempty" db:"-"` // Only set immediately after creation
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty" db:"rotated_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	IsPrimary  bool       `json:"is_primary" db:"is_primary"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
}

type User struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Username  string    `json:"username" db:"username"`
	Email     string    `json:"email" db:"email"`
	Password  string    `json:"-" db:"password"`
	Scopes    []string  `json:"scopes" db:"scopes"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type AuthorizationCode struct {
	ID                uuid.UUID `json:"id" db:"id"`
	Code              string    `json:"code" db:"code"`
	ClientID          string    `json:"client_id" db:"client_id"`
	UserID            uuid.UUID `json:"user_id" db:"user_id"`
	RedirectURI       string    `json:"redirect_uri" db:"redirect_uri"`
	Scopes            []string  `json:"scopes" db:"scopes"`
	CodeChallenge     string    `json:"code_challenge,omitempty" db:"code_challenge"`
	CodeChallengeMethod string  `json:"code_challenge_method,omitempty" db:"code_challenge_method"`
	ExpiresAt         time.Time `json:"expires_at" db:"expires_at"`
	Used              bool      `json:"used" db:"used"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

type AccessToken struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	Token     string     `json:"token" db:"token"`
	ClientID  string     `json:"client_id" db:"client_id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	Scopes    []string   `json:"scopes" db:"scopes"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	Revoked   bool       `json:"revoked" db:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

type RefreshToken struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	Token           string     `json:"token" db:"token"`
	AccessTokenID   uuid.UUID  `json:"access_token_id" db:"access_token_id"`
	ClientID        string     `json:"client_id" db:"client_id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	Scopes          []string   `json:"scopes" db:"scopes"`
	ExpiresAt       time.Time  `json:"expires_at" db:"expires_at"`
	Revoked         bool       `json:"revoked" db:"revoked"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
}

type Scope struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	Name          string     `json:"name" db:"name"`
	Description   string     `json:"description" db:"description"`
	Category      string     `json:"category,omitempty" db:"category"`
	ParentScope   *string    `json:"parent_scope,omitempty" db:"parent_scope"`
	IsDefault     bool       `json:"is_default" db:"is_default"`
	IsSystem      bool       `json:"is_system" db:"is_system"`
	RequiresConsent bool     `json:"requires_consent" db:"requires_consent"`
	IconURL       *string    `json:"icon_url,omitempty" db:"icon_url"`
	DisplayOrder  int        `json:"display_order" db:"display_order"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// ScopeConsent tracks user consent for specific scopes
type ScopeConsent struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	ClientID  string    `json:"client_id" db:"client_id"`
	Scope     string    `json:"scope" db:"scope"`
	Granted   bool      `json:"granted" db:"granted"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// ScopeGroup allows organizing scopes into logical groups
type ScopeGroup struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	DisplayName string    `json:"display_name" db:"display_name"`
	IconURL     *string   `json:"icon_url,omitempty" db:"icon_url"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ScopeGroupMembership links scopes to groups
type ScopeGroupMembership struct {
	ID          uuid.UUID `json:"id" db:"id"`
	ScopeID     uuid.UUID `json:"scope_id" db:"scope_id"`
	GroupID     uuid.UUID `json:"group_id" db:"group_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type DeviceCode struct {
	ID               uuid.UUID `json:"id" db:"id"`
	DeviceCode       string    `json:"device_code" db:"device_code"`
	UserCode         string    `json:"user_code" db:"user_code"`
	VerificationURI  string    `json:"verification_uri" db:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty" db:"verification_uri_complete"`
	ClientID         string    `json:"client_id" db:"client_id"`
	Scopes           []string  `json:"scopes" db:"scopes"`
	ExpiresAt        time.Time `json:"expires_at" db:"expires_at"`
	Interval         int       `json:"interval" db:"interval"`
	UserID           *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Authorized       bool      `json:"authorized" db:"authorized"`
	AccessTokenID    *uuid.UUID `json:"access_token_id,omitempty" db:"access_token_id"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}