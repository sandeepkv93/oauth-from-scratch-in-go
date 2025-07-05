package oidc

import (
	"errors"
	"strings"
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
		"end_session_endpoint":               baseURL + "/logout",
		"check_session_iframe":               baseURL + "/session/check",
		"scopes_supported":                   s.GetSupportedScopes(),
		"response_types_supported":           []string{"code", "id_token", "token id_token", "code id_token", "code token", "code token id_token"},
		"response_modes_supported":           []string{"query", "fragment", "form_post"},
		"grant_types_supported":              []string{"authorization_code", "implicit", "refresh_token", "client_credentials", "password", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"subject_types_supported":            []string{"public"},
		"id_token_signing_alg_values_supported": []string{"HS256", "RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"claims_supported":                   s.GetSupportedClaims(),
		"claims_parameter_supported":         true,
		"request_parameter_supported":        false,
		"request_uri_parameter_supported":    false,
		"require_request_uri_registration":   false,
		"code_challenge_methods_supported":   []string{"plain", "S256"},
		"introspection_endpoint":             baseURL + "/introspect",
		"revocation_endpoint":                baseURL + "/revoke",
		"device_authorization_endpoint":      baseURL + "/device_authorization",
		"frontchannel_logout_supported":     true,
		"frontchannel_logout_session_supported": true,
		"backchannel_logout_supported":      false,
		"backchannel_logout_session_supported": false,
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

type SessionInfo struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	AuthTime  time.Time `json:"auth_time"`
	ExpiresAt time.Time `json:"expires_at"`
	Scopes    []string  `json:"scopes"`
}

type LogoutRequest struct {
	IDTokenHint           string `json:"id_token_hint,omitempty"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri,omitempty"`
	State                 string `json:"state,omitempty"`
}

func (s *Service) ValidateLogoutRequest(req *LogoutRequest, client *db.Client) error {
	if req.PostLogoutRedirectURI != "" {
		valid := false
		for _, uri := range client.RedirectURIs {
			if uri == req.PostLogoutRedirectURI {
				valid = true
				break
			}
		}
		if !valid {
			return errors.New("invalid post logout redirect URI")
		}
	}
	return nil
}

func (s *Service) BuildUserInfoResponseEnhanced(user *db.User, scopes []string) *UserInfoResponse {
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
		case "address":
		case "phone":
		}
	}

	return response
}

func (s *Service) GenerateLogoutURL(postLogoutRedirectURI, state string) string {
	if postLogoutRedirectURI == "" {
		return ""
	}
	
	logoutURL := postLogoutRedirectURI
	if state != "" {
		separator := "?"
		if strings.Contains(logoutURL, "?") {
			separator = "&"
		}
		logoutURL += separator + "state=" + state
	}
	
	return logoutURL
}

func (s *Service) ValidatePromptParameter(prompt string) []string {
	if prompt == "" {
		return []string{}
	}
	
	validPrompts := []string{"none", "login", "consent", "select_account"}
	prompts := strings.Split(prompt, " ")
	
	var validatedPrompts []string
	for _, p := range prompts {
		for _, valid := range validPrompts {
			if p == valid {
				validatedPrompts = append(validatedPrompts, p)
				break
			}
		}
	}
	
	return validatedPrompts
}

func (s *Service) ShouldPromptLogin(prompts []string, authTime time.Time, maxAge int) bool {
	for _, prompt := range prompts {
		if prompt == "login" {
			return true
		}
		if prompt == "none" {
			return false
		}
	}
	
	if maxAge > 0 && time.Since(authTime) > time.Duration(maxAge)*time.Second {
		return true
	}
	
	return false
}

func (s *Service) GetSupportedScopes() []string {
	return []string{"openid", "profile", "email", "address", "phone", "offline_access"}
}

func (s *Service) GetSupportedClaims() []string {
	return []string{
		"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp",
		"name", "given_name", "family_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website",
		"email", "email_verified", "gender", "birthdate", "zoneinfo",
		"locale", "phone_number", "phone_number_verified", "address", "updated_at",
	}
}