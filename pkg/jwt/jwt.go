package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	ClientID string    `json:"client_id"`
	Scopes   []string  `json:"scopes"`
	TokenID  uuid.UUID `json:"token_id"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type Manager struct {
	secret     []byte
	keyManager KeyManager
}

type KeyManager interface {
	SignToken(token *jwt.Token) (string, error)
	VerifyToken(tokenString string) (*jwt.Token, error)
	GetCurrentKeyID() string
}

func NewManager(secret string) *Manager {
	return &Manager{
		secret: []byte(secret),
	}
}

func NewManagerWithKeyManager(secret string, keyManager KeyManager) *Manager {
	return &Manager{
		secret:     []byte(secret),
		keyManager: keyManager,
	}
}

func (m *Manager) GenerateAccessToken(userID uuid.UUID, clientID string, scopes []string, tokenID uuid.UUID, ttl time.Duration) (string, error) {
	return m.GenerateAccessTokenWithClaims(userID, clientID, scopes, tokenID, ttl, nil)
}

func (m *Manager) GenerateAccessTokenWithClaims(userID uuid.UUID, clientID string, scopes []string, tokenID uuid.UUID, ttl time.Duration, customClaims map[string]interface{}) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id":   userID.String(),
		"client_id": clientID,
		"scopes":    scopes,
		"token_id":  tokenID.String(),
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"nbf":       now.Unix(),
		"iss":       "oauth-server",
		"sub":       userID.String(),
		"aud":       []string{clientID},
		"jti":       tokenID.String(),
	}

	// Add custom claims
	for key, value := range customClaims {
		claims[key] = value
	}

	var token *jwt.Token
	if m.keyManager != nil {
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		return m.keyManager.SignToken(token)
	} else {
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return token.SignedString(m.secret)
	}
}

func (m *Manager) ValidateAccessToken(tokenString string) (*Claims, error) {
	if m.keyManager != nil {
		token, err := m.keyManager.VerifyToken(tokenString)
		if err != nil {
			return nil, err
		}
		
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			parsedClaims := &Claims{}
			if userID, ok := claims["user_id"].(string); ok {
				if uid, err := uuid.Parse(userID); err == nil {
					parsedClaims.UserID = uid
				}
			}
			if clientID, ok := claims["client_id"].(string); ok {
				parsedClaims.ClientID = clientID
			}
			if scopes, ok := claims["scopes"].([]interface{}); ok {
				parsedClaims.Scopes = make([]string, len(scopes))
				for i, scope := range scopes {
					if s, ok := scope.(string); ok {
						parsedClaims.Scopes[i] = s
					}
				}
			}
			if tokenID, ok := claims["token_id"].(string); ok {
				if tid, err := uuid.Parse(tokenID); err == nil {
					parsedClaims.TokenID = tid
				}
			}
			return parsedClaims, nil
		}
		return nil, errors.New("invalid token claims")
	} else {
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("invalid signing method")
			}
			return m.secret, nil
		})

		if err != nil {
			return nil, err
		}

		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			return claims, nil
		}

		return nil, errors.New("invalid token")
	}
}

func (m *Manager) GenerateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (m *Manager) GenerateAuthorizationCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (m *Manager) GenerateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (m *Manager) SignToken(token *jwt.Token) (string, error) {
	if m.keyManager != nil {
		return m.keyManager.SignToken(token)
	}
	return token.SignedString(m.secret)
}

func (m *Manager) ParseUnverifiedToken(tokenString string) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	return token, err
}