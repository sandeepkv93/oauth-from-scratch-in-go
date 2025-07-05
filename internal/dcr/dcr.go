package dcr

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"oauth-server/internal/db"
	"oauth-server/internal/scopes"
)

var (
	ErrInvalidClientMetadata      = errors.New("invalid_client_metadata")
	ErrInvalidRedirectURI         = errors.New("invalid_redirect_uri")
	ErrInvalidClientURI           = errors.New("invalid_client_uri")
	ErrUnapprovedSoftwareStatement = errors.New("unapproved_software_statement")
	ErrInvalidSoftwareStatement   = errors.New("invalid_software_statement")
	ErrAccessDenied               = errors.New("access_denied")
	ErrInvalidToken               = errors.New("invalid_token")
)

// Service provides Dynamic Client Registration functionality (RFC 7591)
type Service struct {
	db     db.DatabaseInterface
	scopes *scopes.Service
	config *Config
}

// Config holds configuration for Dynamic Client Registration
type Config struct {
	// Whether client registration is enabled
	RegistrationEnabled bool
	
	// Default scopes granted to new clients
	DefaultScopes []string
	
	// Default grant types granted to new clients
	DefaultGrantTypes []string
	
	// Default response types granted to new clients
	DefaultResponseTypes []string
	
	// Whether to require software statements
	RequireSoftwareStatement bool
	
	// Maximum client secret lifetime (0 = no expiration)
	MaxSecretLifetime time.Duration
	
	// Base URL for registration endpoints
	BaseURL string
}

// ClientRegistrationRequest represents the request to register a new client
type ClientRegistrationRequest struct {
	RedirectURIs                []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod     string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                  []string `json:"grant_types,omitempty"`
	ResponseTypes               []string `json:"response_types,omitempty"`
	ClientName                  string   `json:"client_name,omitempty"`
	ClientURI                   string   `json:"client_uri,omitempty"`
	LogoURI                     string   `json:"logo_uri,omitempty"`
	Scope                       string   `json:"scope,omitempty"`
	Contacts                    []string `json:"contacts,omitempty"`
	TosURI                      string   `json:"tos_uri,omitempty"`
	PolicyURI                   string   `json:"policy_uri,omitempty"`
	JwksURI                     string   `json:"jwks_uri,omitempty"`
	Jwks                        string   `json:"jwks,omitempty"`
	SoftwareID                  string   `json:"software_id,omitempty"`
	SoftwareVersion             string   `json:"software_version,omitempty"`
	SoftwareStatement           string   `json:"software_statement,omitempty"`
	
	// Application type: "web" or "native"
	ApplicationType             string   `json:"application_type,omitempty"`
	
	// Subject type for ID tokens: "public" or "pairwise"
	SubjectType                 string   `json:"subject_type,omitempty"`
	
	// Sector identifier URI for pairwise subject identifiers
	SectorIdentifierURI         string   `json:"sector_identifier_uri,omitempty"`
	
	// ID token signed response algorithm
	IDTokenSignedResponseAlg    string   `json:"id_token_signed_response_alg,omitempty"`
	
	// ID token encrypted response algorithm
	IDTokenEncryptedResponseAlg string   `json:"id_token_encrypted_response_alg,omitempty"`
	
	// ID token encrypted response encryption
	IDTokenEncryptedResponseEnc string   `json:"id_token_encrypted_response_enc,omitempty"`
	
	// Userinfo signed response algorithm
	UserinfoSignedResponseAlg   string   `json:"userinfo_signed_response_alg,omitempty"`
	
	// Userinfo encrypted response algorithm
	UserinfoEncryptedResponseAlg string   `json:"userinfo_encrypted_response_alg,omitempty"`
	
	// Userinfo encrypted response encryption
	UserinfoEncryptedResponseEnc string   `json:"userinfo_encrypted_response_enc,omitempty"`
	
	// Request object signing algorithm
	RequestObjectSigningAlg     string   `json:"request_object_signing_alg,omitempty"`
	
	// Request object encryption algorithm
	RequestObjectEncryptionAlg  string   `json:"request_object_encryption_alg,omitempty"`
	
	// Request object encryption method
	RequestObjectEncryptionEnc  string   `json:"request_object_encryption_enc,omitempty"`
	
	// Default max age for authentication
	DefaultMaxAge               int      `json:"default_max_age,omitempty"`
	
	// Whether authentication time is required
	RequireAuthTime             bool     `json:"require_auth_time,omitempty"`
	
	// Default ACR values
	DefaultACRValues            []string `json:"default_acr_values,omitempty"`
	
	// Initiate login URI
	InitiateLoginURI            string   `json:"initiate_login_uri,omitempty"`
	
	// Request URIs
	RequestURIs                 []string `json:"request_uris,omitempty"`
}

// ClientRegistrationResponse represents the response from client registration
type ClientRegistrationResponse struct {
	ClientID                    string    `json:"client_id"`
	ClientSecret                string    `json:"client_secret,omitempty"`
	ClientIDIssuedAt            int64     `json:"client_id_issued_at"`
	ClientSecretExpiresAt       int64     `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken     string    `json:"registration_access_token"`
	RegistrationClientURI       string    `json:"registration_client_uri"`
	
	// Echo back the registered metadata
	RedirectURIs                []string  `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod     string    `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                  []string  `json:"grant_types,omitempty"`
	ResponseTypes               []string  `json:"response_types,omitempty"`
	ClientName                  string    `json:"client_name,omitempty"`
	ClientURI                   string    `json:"client_uri,omitempty"`
	LogoURI                     string    `json:"logo_uri,omitempty"`
	Scope                       string    `json:"scope,omitempty"`
	Contacts                    []string  `json:"contacts,omitempty"`
	TosURI                      string    `json:"tos_uri,omitempty"`
	PolicyURI                   string    `json:"policy_uri,omitempty"`
	JwksURI                     string    `json:"jwks_uri,omitempty"`
	Jwks                        string    `json:"jwks,omitempty"`
	SoftwareID                  string    `json:"software_id,omitempty"`
	SoftwareVersion             string    `json:"software_version,omitempty"`
}

func NewService(database db.DatabaseInterface, scopeService *scopes.Service, config *Config) *Service {
	return &Service{
		db:     database,
		scopes: scopeService,
		config: config,
	}
}

// RegisterClient registers a new OAuth 2.0 client
func (s *Service) RegisterClient(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	if !s.config.RegistrationEnabled {
		return nil, ErrAccessDenied
	}
	
	// Validate the request
	if err := s.validateRegistrationRequest(req); err != nil {
		return nil, err
	}
	
	// Generate client ID and secret
	clientID, err := s.generateClientID()
	if err != nil {
		return nil, err
	}
	
	clientSecret, err := s.generateClientSecret()
	if err != nil {
		return nil, err
	}
	
	// Generate registration access token
	registrationToken, err := s.generateRegistrationToken()
	if err != nil {
		return nil, err
	}
	
	// Determine client type (public vs confidential)
	isPublic := s.isPublicClient(req)
	
	// Apply defaults
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = s.config.DefaultGrantTypes
	}
	
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = s.config.DefaultResponseTypes
	}
	
	tokenAuthMethod := req.TokenEndpointAuthMethod
	if tokenAuthMethod == "" {
		if isPublic {
			tokenAuthMethod = "none"
		} else {
			tokenAuthMethod = "client_secret_basic"
		}
	}
	
	// Parse and validate scopes
	requestedScopes := strings.Fields(req.Scope)
	if len(requestedScopes) == 0 {
		requestedScopes = s.config.DefaultScopes
	}
	
	// Validate scopes against available scopes
	result, err := s.scopes.ValidateScopes(ctx, requestedScopes, s.config.DefaultScopes)
	if err != nil {
		// Use simple validation as fallback
		requestedScopes = s.config.DefaultScopes
	} else if len(result.Invalid) > 0 {
		return nil, fmt.Errorf("%w: invalid scopes: %v", ErrInvalidClientMetadata, result.Invalid)
	}
	
	now := time.Now()
	client := &db.Client{
		ClientID:                    clientID,
		ClientSecret:                clientSecret,
		Name:                        req.ClientName,
		RedirectURIs:                req.RedirectURIs,
		Scopes:                      requestedScopes,
		GrantTypes:                  grantTypes,
		IsPublic:                    isPublic,
		ClientName:                  &req.ClientName,
		ClientURI:                   &req.ClientURI,
		LogoURI:                     &req.LogoURI,
		ContactEmails:               req.Contacts,
		TosURI:                      &req.TosURI,
		PolicyURI:                   &req.PolicyURI,
		JwksURI:                     &req.JwksURI,
		Jwks:                        &req.Jwks,
		SoftwareID:                  &req.SoftwareID,
		SoftwareVersion:             &req.SoftwareVersion,
		TokenEndpointAuthMethod:     &tokenAuthMethod,
		ResponseTypes:               responseTypes,
		RegistrationAccessToken:     &registrationToken,
		ClientIDIssuedAt:            &now,
	}
	
	// Set client secret expiration if configured
	if s.config.MaxSecretLifetime > 0 {
		expiresAt := now.Add(s.config.MaxSecretLifetime)
		client.ClientSecretExpiresAt = &expiresAt
	}
	
	// Set registration client URI
	registrationURI := fmt.Sprintf("%s/register/%s", s.config.BaseURL, clientID)
	client.RegistrationClientURI = &registrationURI
	
	// Create the client in the database
	if err := s.db.CreateClient(ctx, client); err != nil {
		return nil, err
	}
	
	// Build response
	response := &ClientRegistrationResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        now.Unix(),
		RegistrationAccessToken: registrationToken,
		RegistrationClientURI:   registrationURI,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: tokenAuthMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		Scope:                   strings.Join(requestedScopes, " "),
		Contacts:                req.Contacts,
		TosURI:                  req.TosURI,
		PolicyURI:               req.PolicyURI,
		JwksURI:                 req.JwksURI,
		Jwks:                    req.Jwks,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
	}
	
	// Include client secret for confidential clients
	if !isPublic {
		response.ClientSecret = clientSecret
		if client.ClientSecretExpiresAt != nil {
			response.ClientSecretExpiresAt = client.ClientSecretExpiresAt.Unix()
		}
	}
	
	return response, nil
}

// GetClient retrieves client configuration using registration access token
func (s *Service) GetClient(ctx context.Context, clientID, registrationToken string) (*ClientRegistrationResponse, error) {
	client, err := s.db.GetClientByRegistrationToken(ctx, registrationToken)
	if err != nil {
		return nil, ErrInvalidToken
	}
	
	if client.ClientID != clientID {
		return nil, ErrInvalidToken
	}
	
	return s.buildClientResponse(client), nil
}

// UpdateClient updates client configuration using registration access token
func (s *Service) UpdateClient(ctx context.Context, clientID, registrationToken string, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	client, err := s.db.GetClientByRegistrationToken(ctx, registrationToken)
	if err != nil {
		return nil, ErrInvalidToken
	}
	
	if client.ClientID != clientID {
		return nil, ErrInvalidToken
	}
	
	// Validate the update request
	if err := s.validateRegistrationRequest(req); err != nil {
		return nil, err
	}
	
	// Update client fields
	client.Name = req.ClientName
	client.RedirectURIs = req.RedirectURIs
	client.ClientName = &req.ClientName
	client.ClientURI = &req.ClientURI
	client.LogoURI = &req.LogoURI
	client.ContactEmails = req.Contacts
	client.TosURI = &req.TosURI
	client.PolicyURI = &req.PolicyURI
	client.JwksURI = &req.JwksURI
	client.Jwks = &req.Jwks
	client.SoftwareID = &req.SoftwareID
	client.SoftwareVersion = &req.SoftwareVersion
	client.UpdatedAt = time.Now()
	
	// Update grant types and response types if specified
	if len(req.GrantTypes) > 0 {
		client.GrantTypes = req.GrantTypes
	}
	if len(req.ResponseTypes) > 0 {
		client.ResponseTypes = req.ResponseTypes
	}
	
	// Update token endpoint auth method if specified
	if req.TokenEndpointAuthMethod != "" {
		client.TokenEndpointAuthMethod = &req.TokenEndpointAuthMethod
	}
	
	// Update scopes if specified
	if req.Scope != "" {
		requestedScopes := strings.Fields(req.Scope)
		result, err := s.scopes.ValidateScopes(ctx, requestedScopes, s.config.DefaultScopes)
		if err == nil && len(result.Invalid) == 0 {
			client.Scopes = requestedScopes
		}
	}
	
	// Save the updated client
	if err := s.db.UpdateClient(ctx, client); err != nil {
		return nil, err
	}
	
	return s.buildClientResponse(client), nil
}

// DeleteClient deletes a client using registration access token
func (s *Service) DeleteClient(ctx context.Context, clientID, registrationToken string) error {
	client, err := s.db.GetClientByRegistrationToken(ctx, registrationToken)
	if err != nil {
		return ErrInvalidToken
	}
	
	if client.ClientID != clientID {
		return ErrInvalidToken
	}
	
	return s.db.DeleteClient(ctx, clientID)
}

// Helper methods

func (s *Service) validateRegistrationRequest(req *ClientRegistrationRequest) error {
	// Validate redirect URIs
	for _, uri := range req.RedirectURIs {
		if err := s.validateRedirectURI(uri); err != nil {
			return err
		}
	}
	
	// Validate client URI
	if req.ClientURI != "" {
		if err := s.validateURI(req.ClientURI); err != nil {
			return fmt.Errorf("%w: client_uri", ErrInvalidClientURI)
		}
	}
	
	// Validate logo URI
	if req.LogoURI != "" {
		if err := s.validateURI(req.LogoURI); err != nil {
			return fmt.Errorf("%w: logo_uri", ErrInvalidClientURI)
		}
	}
	
	// Validate ToS URI
	if req.TosURI != "" {
		if err := s.validateURI(req.TosURI); err != nil {
			return fmt.Errorf("%w: tos_uri", ErrInvalidClientURI)
		}
	}
	
	// Validate policy URI
	if req.PolicyURI != "" {
		if err := s.validateURI(req.PolicyURI); err != nil {
			return fmt.Errorf("%w: policy_uri", ErrInvalidClientURI)
		}
	}
	
	// Validate JWKS URI
	if req.JwksURI != "" {
		if err := s.validateURI(req.JwksURI); err != nil {
			return fmt.Errorf("%w: jwks_uri", ErrInvalidClientURI)
		}
	}
	
	// Validate that either JWKS URI or JWKS is provided, not both
	if req.JwksURI != "" && req.Jwks != "" {
		return fmt.Errorf("%w: cannot specify both jwks_uri and jwks", ErrInvalidClientMetadata)
	}
	
	return nil
}

func (s *Service) validateRedirectURI(uri string) error {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidRedirectURI, uri)
	}
	
	// RFC 6749: redirect URIs must be absolute
	if !parsedURI.IsAbs() {
		return fmt.Errorf("%w: redirect URI must be absolute: %s", ErrInvalidRedirectURI, uri)
	}
	
	// RFC 6749: redirect URIs must not contain fragments
	if parsedURI.Fragment != "" {
		return fmt.Errorf("%w: redirect URI must not contain fragment: %s", ErrInvalidRedirectURI, uri)
	}
	
	return nil
}

func (s *Service) validateURI(uri string) error {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return err
	}
	
	// URI must be absolute and use HTTPS (or HTTP for localhost in development)
	if !parsedURI.IsAbs() {
		return errors.New("URI must be absolute")
	}
	
	if parsedURI.Scheme != "https" && !(parsedURI.Scheme == "http" && parsedURI.Hostname() == "localhost") {
		return errors.New("URI must use HTTPS")
	}
	
	return nil
}

func (s *Service) isPublicClient(req *ClientRegistrationRequest) bool {
	// Native applications are typically public clients
	if req.ApplicationType == "native" {
		return true
	}
	
	// Clients with no authentication method are public
	if req.TokenEndpointAuthMethod == "none" {
		return true
	}
	
	// Check for custom redirect URI schemes (indicating native app)
	for _, uri := range req.RedirectURIs {
		parsedURI, err := url.Parse(uri)
		if err == nil && parsedURI.Scheme != "https" && parsedURI.Scheme != "http" {
			return true
		}
	}
	
	return false
}

func (s *Service) generateClientID() (string, error) {
	// Generate a unique client ID
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Service) generateClientSecret() (string, error) {
	// Generate a strong client secret
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Service) generateRegistrationToken() (string, error) {
	// Generate a registration access token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Service) buildClientResponse(client *db.Client) *ClientRegistrationResponse {
	response := &ClientRegistrationResponse{
		ClientID:                client.ClientID,
		RegistrationAccessToken: *client.RegistrationAccessToken,
		RegistrationClientURI:   *client.RegistrationClientURI,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		Scope:                   strings.Join(client.Scopes, " "),
		Contacts:                client.ContactEmails,
	}
	
	if client.ClientIDIssuedAt != nil {
		response.ClientIDIssuedAt = client.ClientIDIssuedAt.Unix()
	}
	
	if !client.IsPublic {
		response.ClientSecret = client.ClientSecret
		if client.ClientSecretExpiresAt != nil {
			response.ClientSecretExpiresAt = client.ClientSecretExpiresAt.Unix()
		}
	}
	
	if client.ClientName != nil {
		response.ClientName = *client.ClientName
	}
	if client.ClientURI != nil {
		response.ClientURI = *client.ClientURI
	}
	if client.LogoURI != nil {
		response.LogoURI = *client.LogoURI
	}
	if client.TosURI != nil {
		response.TosURI = *client.TosURI
	}
	if client.PolicyURI != nil {
		response.PolicyURI = *client.PolicyURI
	}
	if client.JwksURI != nil {
		response.JwksURI = *client.JwksURI
	}
	if client.Jwks != nil {
		response.Jwks = *client.Jwks
	}
	if client.SoftwareID != nil {
		response.SoftwareID = *client.SoftwareID
	}
	if client.SoftwareVersion != nil {
		response.SoftwareVersion = *client.SoftwareVersion
	}
	if client.TokenEndpointAuthMethod != nil {
		response.TokenEndpointAuthMethod = *client.TokenEndpointAuthMethod
	}
	
	return response
}