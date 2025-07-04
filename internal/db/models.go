package db

import (
	"time"

	"github.com/google/uuid"
)

type Client struct {
	ID           uuid.UUID `json:"id" db:"id"`
	ClientID     string    `json:"client_id" db:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty" db:"client_secret"`
	Name         string    `json:"name" db:"name"`
	RedirectURIs []string  `json:"redirect_uris" db:"redirect_uris"`
	Scopes       []string  `json:"scopes" db:"scopes"`
	GrantTypes   []string  `json:"grant_types" db:"grant_types"`
	IsPublic     bool      `json:"is_public" db:"is_public"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
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
	ID        uuid.UUID `json:"id" db:"id"`
	Token     string    `json:"token" db:"token"`
	ClientID  string    `json:"client_id" db:"client_id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Scopes    []string  `json:"scopes" db:"scopes"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Revoked   bool      `json:"revoked" db:"revoked"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type RefreshToken struct {
	ID              uuid.UUID `json:"id" db:"id"`
	Token           string    `json:"token" db:"token"`
	AccessTokenID   uuid.UUID `json:"access_token_id" db:"access_token_id"`
	ClientID        string    `json:"client_id" db:"client_id"`
	UserID          uuid.UUID `json:"user_id" db:"user_id"`
	Scopes          []string  `json:"scopes" db:"scopes"`
	ExpiresAt       time.Time `json:"expires_at" db:"expires_at"`
	Revoked         bool      `json:"revoked" db:"revoked"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

type Scope struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	IsDefault   bool      `json:"is_default" db:"is_default"`
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