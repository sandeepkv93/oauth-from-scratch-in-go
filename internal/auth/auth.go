package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/config"
	"oauth-server/internal/db"
	"oauth-server/pkg/crypto"
	"oauth-server/pkg/jwt"
)

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrInvalidClient          = errors.New("invalid client")
	ErrInvalidGrant           = errors.New("invalid grant")
	ErrInvalidScope           = errors.New("invalid scope")
	ErrInvalidRedirectURI     = errors.New("invalid redirect URI")
	ErrExpiredCode            = errors.New("authorization code expired")
	ErrUsedCode               = errors.New("authorization code already used")
	ErrInvalidCodeChallenge   = errors.New("invalid code challenge")
	ErrInvalidCodeVerifier    = errors.New("invalid code verifier")
	ErrCodeChallengeMismatch  = errors.New("code challenge verification failed")
	ErrAuthorizationPending   = errors.New("authorization_pending")
	ErrSlowDown               = errors.New("slow_down")
	ErrAccessDenied           = errors.New("access_denied")
	ErrExpiredToken           = errors.New("expired_token")
)

type Service struct {
	db       db.DatabaseInterface
	jwt      *jwt.Manager
	pkce     *crypto.PKCEManager
	config   *config.Config
}

type AuthorizeRequest struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	DeviceCode   string `json:"device_code,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type DeviceAuthorizationRequest struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func NewService(database db.DatabaseInterface, jwtManager *jwt.Manager, cfg *config.Config) *Service {
	return &Service{
		db:     database,
		jwt:    jwtManager,
		pkce:   crypto.NewPKCEManager(),
		config: cfg,
	}
}

func (s *Service) AuthenticateUser(username, password string) (*db.User, error) {
	user, err := s.db.GetUserByUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

func (s *Service) ValidateClient(clientID, clientSecret string) (*db.Client, error) {
	client, err := s.db.GetClientByID(clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if !client.IsPublic {
		if clientSecret == "" {
			return nil, ErrInvalidClient
		}
		
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret)); err != nil {
			return nil, ErrInvalidClient
		}
	}

	return client, nil
}

func (s *Service) ValidateRedirectURI(client *db.Client, redirectURI string) error {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return nil
		}
	}
	return ErrInvalidRedirectURI
}

func (s *Service) ValidateScopes(requestedScopes []string, allowedScopes []string) error {
	for _, scope := range requestedScopes {
		found := false
		for _, allowed := range allowedScopes {
			if scope == allowed {
				found = true
				break
			}
		}
		if !found {
			return ErrInvalidScope
		}
	}
	return nil
}

func (s *Service) CreateAuthorizationCode(userID uuid.UUID, clientID, redirectURI string, scopes []string, codeChallenge, codeChallengeMethod string) (string, error) {
	code, err := s.jwt.GenerateAuthorizationCode()
	if err != nil {
		return "", err
	}

	if codeChallenge != "" {
		if !s.pkce.IsValidCodeChallenge(codeChallenge) {
			return "", ErrInvalidCodeChallenge
		}
		if !s.pkce.IsSupportedMethod(codeChallengeMethod) {
			return "", ErrInvalidCodeChallenge
		}
	}

	authCode := &db.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(s.config.Auth.AuthorizationCodeTTL),
	}

	if err := s.db.CreateAuthorizationCode(authCode); err != nil {
		return "", err
	}

	return code, nil
}

func (s *Service) ExchangeCodeForToken(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	if !s.hasGrantType(client, "authorization_code") {
		return nil, ErrInvalidGrant
	}

	authCode, err := s.db.GetAuthorizationCode(req.Code)
	if err != nil {
		return nil, ErrExpiredCode
	}

	if authCode.Used {
		return nil, ErrUsedCode
	}

	if authCode.ClientID != req.ClientID {
		return nil, ErrInvalidClient
	}

	if authCode.RedirectURI != req.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, ErrInvalidCodeVerifier
		}
		
		if err := s.pkce.VerifyCodeChallenge(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			return nil, ErrCodeChallengeMismatch
		}
	} else if client.IsPublic {
		return nil, ErrInvalidCodeChallenge
	}

	if err := s.db.MarkAuthorizationCodeUsed(req.Code); err != nil {
		return nil, err
	}

	return s.createTokenPair(authCode.UserID, authCode.ClientID, authCode.Scopes)
}

func (s *Service) RefreshAccessToken(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	if !s.hasGrantType(client, "refresh_token") {
		return nil, ErrInvalidGrant
	}

	refreshToken, err := s.db.GetRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	if refreshToken.ClientID != req.ClientID {
		return nil, ErrInvalidClient
	}

	if err := s.db.RevokeAccessToken(refreshToken.AccessTokenID); err != nil {
		return nil, err
	}

	if err := s.db.RevokeRefreshToken(req.RefreshToken); err != nil {
		return nil, err
	}

	scopes := refreshToken.Scopes
	if req.Scope != "" {
		requestedScopes := strings.Split(req.Scope, " ")
		if err := s.ValidateScopes(requestedScopes, refreshToken.Scopes); err != nil {
			return nil, err
		}
		scopes = requestedScopes
	}

	return s.createTokenPair(refreshToken.UserID, refreshToken.ClientID, scopes)
}

func (s *Service) ClientCredentialsGrant(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	if !s.hasGrantType(client, "client_credentials") {
		return nil, ErrInvalidGrant
	}

	scopes := client.Scopes
	if req.Scope != "" {
		requestedScopes := strings.Split(req.Scope, " ")
		if err := s.ValidateScopes(requestedScopes, client.Scopes); err != nil {
			return nil, err
		}
		scopes = requestedScopes
	}

	return s.createTokenPair(uuid.Nil, req.ClientID, scopes)
}

func (s *Service) ResourceOwnerPasswordCredentialsGrant(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	if !s.hasGrantType(client, "password") {
		return nil, ErrInvalidGrant
	}

	if req.Username == "" || req.Password == "" {
		return nil, errors.New("username and password required")
	}

	user, err := s.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	scopes := client.Scopes
	if req.Scope != "" {
		requestedScopes := strings.Split(req.Scope, " ")
		if err := s.ValidateScopes(requestedScopes, client.Scopes); err != nil {
			return nil, err
		}
		scopes = requestedScopes
	}

	return s.createTokenPair(user.ID, req.ClientID, scopes)
}

func (s *Service) InitiateDeviceAuthorization(req *DeviceAuthorizationRequest, baseURL string) (*DeviceAuthorizationResponse, error) {
	client, err := s.db.GetClientByID(req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if !s.hasGrantType(client, "urn:ietf:params:oauth:grant-type:device_code") {
		return nil, ErrInvalidGrant
	}

	scopes := []string{}
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
		if err := s.ValidateScopes(scopes, client.Scopes); err != nil {
			return nil, err
		}
	}

	deviceCode, err := s.generateDeviceCode()
	if err != nil {
		return nil, err
	}

	userCode, err := s.generateUserCode()
	if err != nil {
		return nil, err
	}

	verificationURI := baseURL + "/device"
	verificationURIComplete := fmt.Sprintf("%s?user_code=%s", verificationURI, userCode)
	expiresIn := int64(600) // 10 minutes
	interval := 5           // 5 seconds

	deviceCodeRecord := &db.DeviceCode{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ClientID:                req.ClientID,
		Scopes:                  scopes,
		ExpiresAt:               time.Now().Add(time.Duration(expiresIn) * time.Second),
		Interval:                interval,
	}

	if err := s.db.CreateDeviceCode(deviceCodeRecord); err != nil {
		return nil, err
	}

	return &DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               expiresIn,
		Interval:                interval,
	}, nil
}

func (s *Service) DeviceCodeGrant(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	if !s.hasGrantType(client, "urn:ietf:params:oauth:grant-type:device_code") {
		return nil, ErrInvalidGrant
	}

	deviceCode, err := s.db.GetDeviceCode(req.DeviceCode)
	if err != nil {
		return nil, ErrExpiredToken
	}

	if deviceCode.ClientID != req.ClientID {
		return nil, ErrInvalidClient
	}

	if !deviceCode.Authorized {
		return nil, ErrAuthorizationPending
	}

	if deviceCode.UserID == nil {
		return nil, ErrAccessDenied
	}

	return s.createTokenPair(*deviceCode.UserID, req.ClientID, deviceCode.Scopes)
}

func (s *Service) AuthorizeDeviceCode(userCode string, userID uuid.UUID) error {
	_, err := s.db.GetDeviceCodeByUserCode(userCode)
	if err != nil {
		return errors.New("invalid user code")
	}

	return s.db.AuthorizeDeviceCode(userCode, userID)
}

func (s *Service) generateDeviceCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Service) generateUserCode() (string, error) {
	const charset = "BCDFGHJKLMNPQRSTVWXZ23456789"
	const length = 8
	
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
		
		if i == 3 {
			result = append(result[:i+1], append([]byte{'-'}, result[i+1:]...)...)
			i++
		}
	}
	
	return string(result), nil
}

func (s *Service) createTokenPair(userID uuid.UUID, clientID string, scopes []string) (*TokenResponse, error) {
	tokenID := uuid.New()
	
	accessToken, err := s.jwt.GenerateAccessToken(userID, clientID, scopes, tokenID, s.config.Auth.AccessTokenTTL)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	dbAccessToken := &db.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(s.config.Auth.AccessTokenTTL),
	}

	if err := s.db.CreateAccessToken(dbAccessToken); err != nil {
		return nil, err
	}

	dbRefreshToken := &db.RefreshToken{
		Token:           refreshToken,
		AccessTokenID:   dbAccessToken.ID,
		ClientID:        clientID,
		UserID:          userID,
		Scopes:          scopes,
		ExpiresAt:       time.Now().Add(s.config.Auth.RefreshTokenTTL),
	}

	if err := s.db.CreateRefreshToken(dbRefreshToken); err != nil {
		return nil, err
	}

	response := &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.Auth.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        strings.Join(scopes, " "),
	}

	return response, nil
}

func (s *Service) hasGrantType(client *db.Client, grantType string) bool {
	for _, gt := range client.GrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

func (s *Service) ValidateAccessToken(token string) (*jwt.Claims, error) {
	return s.jwt.ValidateAccessToken(token)
}

func (s *Service) ValidatePasswordStrength(password string) error {
	minLength := s.config.Security.MinPasswordLength
	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters long", minLength)
	}
	
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false
	
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*(),.?\":{}|<>", char):
			hasSpecial = true
		}
	}
	
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}
	
	return nil
}

func (s *Service) HashPassword(password string) (string, error) {
	if err := s.ValidatePasswordStrength(password); err != nil {
		return "", err
	}
	
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (s *Service) CreateRedirectURL(redirectURI, code, state string) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Service) CreateErrorRedirectURL(redirectURI, errorType, description, state string) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errorType)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}