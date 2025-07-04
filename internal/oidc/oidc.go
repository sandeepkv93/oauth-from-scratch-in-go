package oidc

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"oauth-server/internal/db"
	jwtpkg "oauth-server/pkg/jwt"
)

type IDTokenClaims struct {
	Issuer             string    `json:"iss"`
	Subject            string    `json:"sub"`
	Audience           []string  `json:"aud"`
	ExpiresAt          int64     `json:"exp"`
	IssuedAt           int64     `json:"iat"`
	AuthTime           int64     `json:"auth_time,omitempty"`
	Nonce              string    `json:"nonce,omitempty"`
	AuthContextClassRef string   `json:"acr,omitempty"`
	AuthMethodsRefs    []string  `json:"amr,omitempty"`
	AuthorizedParty    string    `json:"azp,omitempty"`
	
	Name               string    `json:"name,omitempty"`
	GivenName          string    `json:"given_name,omitempty"`
	FamilyName         string    `json:"family_name,omitempty"`
	MiddleName         string    `json:"middle_name,omitempty"`
	Nickname           string    `json:"nickname,omitempty"`
	PreferredUsername  string    `json:"preferred_username,omitempty"`
	Profile            string    `json:"profile,omitempty"`
	Picture            string    `json:"picture,omitempty"`
	Website            string    `json:"website,omitempty"`
	Email              string    `json:"email,omitempty"`
	EmailVerified      bool      `json:"email_verified,omitempty"`
	Gender             string    `json:"gender,omitempty"`
	Birthdate          string    `json:"birthdate,omitempty"`
	Zoneinfo           string    `json:"zoneinfo,omitempty"`
	Locale             string    `json:"locale,omitempty"`
	PhoneNumber        string    `json:"phone_number,omitempty"`
	PhoneNumberVerified bool     `json:"phone_number_verified,omitempty"`
	Address            *Address  `json:"address,omitempty"`
	UpdatedAt          int64     `json:"updated_at,omitempty"`
}

type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

type UserInfoResponse struct {
	Subject            string   `json:"sub"`
	Name               string   `json:"name,omitempty"`
	GivenName          string   `json:"given_name,omitempty"`
	FamilyName         string   `json:"family_name,omitempty"`
	MiddleName         string   `json:"middle_name,omitempty"`
	Nickname           string   `json:"nickname,omitempty"`
	PreferredUsername  string   `json:"preferred_username,omitempty"`
	Profile            string   `json:"profile,omitempty"`
	Picture            string   `json:"picture,omitempty"`
	Website            string   `json:"website,omitempty"`
	Email              string   `json:"email,omitempty"`
	EmailVerified      bool     `json:"email_verified,omitempty"`
	Gender             string   `json:"gender,omitempty"`
	Birthdate          string   `json:"birthdate,omitempty"`
	Zoneinfo           string   `json:"zoneinfo,omitempty"`
	Locale             string   `json:"locale,omitempty"`
	PhoneNumber        string   `json:"phone_number,omitempty"`
	PhoneNumberVerified bool    `json:"phone_number_verified,omitempty"`
	Address            *Address `json:"address,omitempty"`
	UpdatedAt          int64    `json:"updated_at,omitempty"`
}

type Service struct {
	jwtManager *jwtpkg.Manager
	issuer     string
}

func NewService(jwtManager *jwtpkg.Manager, issuer string) *Service {
	return &Service{
		jwtManager: jwtManager,
		issuer:     issuer,
	}
}

func (s *Service) GenerateIDToken(user *db.User, clientID string, nonce string, authTime time.Time, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := IDTokenClaims{
		Issuer:            s.issuer,
		Subject:           user.ID.String(),
		Audience:          []string{clientID},
		ExpiresAt:         now.Add(ttl).Unix(),
		IssuedAt:          now.Unix(),
		AuthTime:          authTime.Unix(),
		Nonce:             nonce,
		PreferredUsername: user.Username,
		Email:             user.Email,
		EmailVerified:     true,
		UpdatedAt:         user.UpdatedAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":                claims.Issuer,
		"sub":                claims.Subject,
		"aud":                claims.Audience,
		"exp":                claims.ExpiresAt,
		"iat":                claims.IssuedAt,
		"auth_time":          claims.AuthTime,
		"nonce":              claims.Nonce,
		"preferred_username": claims.PreferredUsername,
		"email":              claims.Email,
		"email_verified":     claims.EmailVerified,
		"updated_at":         claims.UpdatedAt,
	})

	return s.jwtManager.SignToken(token)
}

func (s *Service) BuildUserInfoResponse(user *db.User, scopes []string) *UserInfoResponse {
	response := &UserInfoResponse{
		Subject: user.ID.String(),
	}

	for _, scope := range scopes {
		switch scope {
		case "profile":
			response.PreferredUsername = user.Username
			response.UpdatedAt = user.UpdatedAt.Unix()
		case "email":
			response.Email = user.Email
			response.EmailVerified = true
		}
	}

	return response
}

func (s *Service) GetWellKnownConfiguration(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"issuer":                              s.issuer,
		"authorization_endpoint":              baseURL + "/authorize",
		"token_endpoint":                     baseURL + "/token",
		"userinfo_endpoint":                  baseURL + "/userinfo",
		"jwks_uri":                           baseURL + "/.well-known/jwks.json",
		"registration_endpoint":              baseURL + "/api/clients",
		"scopes_supported":                   []string{"openid", "profile", "email", "address", "phone"},
		"response_types_supported":           []string{"code", "id_token", "token id_token", "code id_token", "code token", "code token id_token"},
		"response_modes_supported":           []string{"query", "fragment", "form_post"},
		"grant_types_supported":              []string{"authorization_code", "implicit", "refresh_token", "client_credentials", "password"},
		"subject_types_supported":            []string{"public"},
		"id_token_signing_alg_values_supported": []string{"HS256", "RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
			"name", "given_name", "family_name", "middle_name", "nickname",
			"preferred_username", "profile", "picture", "website",
			"email", "email_verified", "gender", "birthdate", "zoneinfo",
			"locale", "phone_number", "phone_number_verified", "address", "updated_at",
		},
		"code_challenge_methods_supported": []string{"plain", "S256"},
		"introspection_endpoint":           baseURL + "/introspect",
		"revocation_endpoint":              baseURL + "/revoke",
	}
}

func (s *Service) HasOpenIDScope(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "openid" {
			return true
		}
	}
	return false
}