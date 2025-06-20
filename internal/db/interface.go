package db

import "github.com/google/uuid"

type DatabaseInterface interface {
	CreateUser(user *User) error
	GetUserByUsername(username string) (*User, error)
	GetUserByID(id uuid.UUID) (*User, error)
	CreateClient(client *Client) error
	GetClientByID(clientID string) (*Client, error)
	CreateAuthorizationCode(code *AuthorizationCode) error
	GetAuthorizationCode(code string) (*AuthorizationCode, error)
	MarkAuthorizationCodeUsed(code string) error
	CreateAccessToken(token *AccessToken) error
	CreateRefreshToken(token *RefreshToken) error
	GetAccessToken(token string) (*AccessToken, error)
	GetRefreshToken(token string) (*RefreshToken, error)
	RevokeAccessToken(tokenID uuid.UUID) error
	RevokeRefreshToken(token string) error
	Close() error
}