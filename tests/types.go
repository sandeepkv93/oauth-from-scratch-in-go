package tests

import (
	"oauth-server/internal/db"
)

// Type aliases for easier access in test server
type User = db.User
type Client = db.Client
type AuthorizationCode = db.AuthorizationCode
type AccessToken = db.AccessToken
type RefreshToken = db.RefreshToken
type DatabaseInterface = db.DatabaseInterface