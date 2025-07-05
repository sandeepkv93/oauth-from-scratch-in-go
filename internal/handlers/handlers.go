package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"oauth-server/internal/auth"
	"oauth-server/internal/db"
	"oauth-server/internal/oidc"
)

type Handler struct {
	auth *auth.Service
	db   db.DatabaseInterface
	oidc *oidc.Service
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func NewHandler(authService *auth.Service, database db.DatabaseInterface, oidcService *oidc.Service) *Handler {
	return &Handler{
		auth: authService,
		db:   database,
		oidc: oidcService,
	}
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/authorize", h.Authorize).Methods("GET", "POST")
	r.HandleFunc("/token", h.Token).Methods("POST")
	r.HandleFunc("/device_authorization", h.DeviceAuthorization).Methods("POST")
	r.HandleFunc("/device", h.DeviceVerification).Methods("GET", "POST")
	r.HandleFunc("/introspect", h.Introspect).Methods("POST")
	r.HandleFunc("/userinfo", h.UserInfo).Methods("GET")
	r.HandleFunc("/revoke", h.Revoke).Methods("POST")
	r.HandleFunc("/login", h.Login).Methods("GET", "POST")
	r.HandleFunc("/logout", h.Logout).Methods("GET", "POST")
	r.HandleFunc("/session/check", h.CheckSession).Methods("GET")
	r.HandleFunc("/session/iframe", h.SessionIframe).Methods("GET")
	
	apiRouter := r.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/clients", h.CreateClient).Methods("POST")
	apiRouter.HandleFunc("/clients", h.ListClients).Methods("GET")
	apiRouter.HandleFunc("/users", h.CreateUser).Methods("POST")
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		h.showAuthorizePage(w, r)
		return
	}
	
	h.handleAuthorizePost(w, r)
}

func (h *Handler) showAuthorizePage(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	redirectURI := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	responseType := strings.TrimSpace(r.URL.Query().Get("response_type"))
	codeChallenge := strings.TrimSpace(r.URL.Query().Get("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(r.URL.Query().Get("code_challenge_method"))
	nonce := strings.TrimSpace(r.URL.Query().Get("nonce"))
	prompt := strings.TrimSpace(r.URL.Query().Get("prompt"))
	maxAge := r.URL.Query().Get("max_age")

	if err := h.validateBasicParams(clientID, redirectURI, responseType); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if responseType != "code" && responseType != "token" {
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}

	client, err := h.db.GetClientByID(r.Context(), clientID)
	if err != nil {
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}

	if err := h.auth.ValidateRedirectURI(client, redirectURI); err != nil {
		http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
		return
	}

	scopes := []string{}
	if scope != "" {
		scopes = strings.Split(scope, " ")
	}

	if err := h.auth.ValidateScopes(scopes, client.Scopes); err != nil {
		redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "invalid_scope", "Invalid scope requested", state)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	prompts := h.oidc.ValidatePromptParameter(prompt)
	_ = maxAge

	for _, p := range prompts {
		if p == "none" {
			redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "interaction_required", "User interaction required", state)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
	}

	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize Application</title>
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px; 
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 { 
            color: #2c3e50; 
            margin-bottom: 20px;
            text-align: center;
        }
        .form-group { margin-bottom: 20px; }
        label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 600;
            color: #555;
        }
        input { 
            width: 100%; 
            padding: 12px; 
            border: 2px solid #e1e8ed; 
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        .button-group {
            display: flex;
            gap: 12px;
            margin-top: 30px;
        }
        button { 
            flex: 1;
            padding: 12px 24px; 
            border: none; 
            border-radius: 6px; 
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
        }
        .btn-authorize {
            background: #28a745; 
            color: white;
        }
        .btn-authorize:hover { 
            background: #218838;
            transform: translateY(-1px);
        }
        .btn-deny {
            background: #dc3545;
            color: white;
        }
        .btn-deny:hover { 
            background: #c82333;
            transform: translateY(-1px);
        }
        .client-info { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 6px; 
            margin-bottom: 25px;
            border-left: 4px solid #007bff;
        }
        .client-info h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .scopes { 
            background: #e7f3ff; 
            padding: 15px; 
            border-radius: 6px; 
            margin-top: 15px;
        }
        .scopes ul {
            margin: 10px 0 0 0;
            padding-left: 20px;
        }
        .scopes li {
            margin-bottom: 5px;
            color: #495057;
        }
        @media (max-width: 600px) {
            body { margin: 20px; padding: 15px; }
            .container { padding: 20px; }
            .button-group { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Authorize Application</h2>
        <div class="client-info">
            <h3>{{.ClientName}}</h3>
            <p>This application is requesting access to your account. Please review the requested permissions below.</p>
            {{if .Scopes}}
            <div class="scopes">
                <strong>📋 Requested permissions:</strong>
                <ul>
                    {{range .Scopes}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
            </div>
            {{end}}
        </div>
        
        <form method="post">
            <input type="hidden" name="client_id" value="{{.ClientID}}">
            <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
            <input type="hidden" name="scope" value="{{.Scope}}">
            <input type="hidden" name="state" value="{{.State}}">
            <input type="hidden" name="response_type" value="{{.ResponseType}}">
            <input type="hidden" name="nonce" value="{{.Nonce}}">
            <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
            <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
            
            <div class="form-group">
                <label for="username">👤 Username:</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">🔑 Password:</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            
            <div class="button-group">
                <button type="submit" name="action" value="authorize" class="btn-authorize">✅ Authorize</button>
                <button type="submit" name="action" value="deny" class="btn-deny">❌ Deny</button>
            </div>
        </form>
    </div>
</body>
</html>`

	t, err := template.New("authorize").Parse(tmpl)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	data := struct {
		ClientID            string
		ClientName          string
		RedirectURI         string
		Scope               string
		Scopes              []string
		State               string
		ResponseType        string
		CodeChallenge       string
		CodeChallengeMethod string
		Nonce               string
	}{
		ClientID:            template.HTMLEscapeString(clientID),
		ClientName:          template.HTMLEscapeString(client.Name),
		RedirectURI:         template.HTMLEscapeString(redirectURI),
		Scope:               template.HTMLEscapeString(scope),
		Scopes:              scopes,
		State:               template.HTMLEscapeString(state),
		ResponseType:        template.HTMLEscapeString(responseType),
		CodeChallenge:       template.HTMLEscapeString(codeChallenge),
		CodeChallengeMethod: template.HTMLEscapeString(codeChallengeMethod),
		Nonce:               template.HTMLEscapeString(nonce),
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	
	action := strings.TrimSpace(r.FormValue("action"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	scope := strings.TrimSpace(r.FormValue("scope"))
	state := strings.TrimSpace(r.FormValue("state"))
	responseType := strings.TrimSpace(r.FormValue("response_type"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	codeChallenge := strings.TrimSpace(r.FormValue("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(r.FormValue("code_challenge_method"))
	nonce := strings.TrimSpace(r.FormValue("nonce"))

	if err := h.validateBasicParams(clientID, redirectURI, responseType); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if action == "deny" {
		redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "access_denied", "User denied the request", state)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	if err := h.validateCredentials(username, password); err != nil {
		redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "invalid_request", err.Error(), state)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	user, err := h.auth.AuthenticateUser(r.Context(), username, password)
	if err != nil {
		redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "access_denied", "Invalid credentials", state)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	scopes := []string{}
	if scope != "" {
		scopes = strings.Split(scope, " ")
	}

	// Handle different response types
	switch responseType {
	case "code":
		// Authorization Code Flow
		code, err := h.auth.CreateAuthorizationCode(r.Context(), user.ID, clientID, redirectURI, scopes, codeChallenge, codeChallengeMethod)
		if err != nil {
			redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "server_error", "Failed to create authorization code", state)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		redirectURL := h.auth.CreateRedirectURL(redirectURI, code, state)
		http.Redirect(w, r, redirectURL, http.StatusFound)

	case "token":
		// Implicit Grant Flow
		authReq := &auth.AuthorizeRequest{
			ResponseType: responseType,
			ClientID:     clientID,
			RedirectURI:  redirectURI,
			Scope:        scope,
			State:        state,
			Nonce:        nonce,
		}

		response, err := h.auth.ImplicitGrant(r.Context(), authReq, user.ID)
		if err != nil {
			redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "server_error", "Failed to generate tokens", state)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		// Generate ID token if needed
		if response.GenerateIDToken {
			idToken, err := h.generateIDTokenForImplicit(authReq, response, user)
			if err == nil {
				response.IDToken = idToken
			}
		}

		redirectURL := h.auth.CreateImplicitRedirectURL(redirectURI, response)
		http.Redirect(w, r, redirectURL, http.StatusFound)

	default:
		redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "unsupported_response_type", "Unsupported response type", state)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	r.ParseForm()
	
	req := &auth.TokenRequest{
		GrantType:          r.FormValue("grant_type"),
		Code:               r.FormValue("code"),
		RedirectURI:        r.FormValue("redirect_uri"),
		ClientID:           r.FormValue("client_id"),
		ClientSecret:       r.FormValue("client_secret"),
		RefreshToken:       r.FormValue("refresh_token"),
		Scope:              r.FormValue("scope"),
		CodeVerifier:       r.FormValue("code_verifier"),
		Username:           r.FormValue("username"),
		Password:           r.FormValue("password"),
		DeviceCode:         r.FormValue("device_code"),
		Assertion:          r.FormValue("assertion"),
		// Token Exchange fields (RFC 8693)
		SubjectToken:       r.FormValue("subject_token"),
		SubjectTokenType:   r.FormValue("subject_token_type"),
		ActorToken:         r.FormValue("actor_token"),
		ActorTokenType:     r.FormValue("actor_token_type"),
		RequestedTokenType: r.FormValue("requested_token_type"),
		Audience:           r.FormValue("audience"),
		Resource:           r.FormValue("resource"),
	}

	var response *auth.TokenResponse
	var err error

	switch req.GrantType {
	case "authorization_code":
		response, err = h.auth.ExchangeCodeForToken(r.Context(), req)
	case "refresh_token":
		response, err = h.auth.RefreshAccessToken(r.Context(), req)
	case "client_credentials":
		response, err = h.auth.ClientCredentialsGrant(r.Context(), req)
	case "password":
		response, err = h.auth.ResourceOwnerPasswordCredentialsGrant(r.Context(), req)
	case "urn:ietf:params:oauth:grant-type:device_code":
		response, err = h.auth.DeviceCodeGrant(r.Context(), req)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		response, err = h.auth.JWTBearerGrant(r.Context(), req)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		response, err = h.auth.TokenExchange(r.Context(), req)
	default:
		h.sendError(w, "unsupported_grant_type", "Grant type not supported", http.StatusBadRequest)
		return
	}

	if err != nil {
		h.handleTokenError(w, err)
		return
	}

	if response != nil && h.shouldGenerateIDToken(req, response) {
		idToken, err := h.generateIDToken(req, response)
		if err == nil {
			response.IDToken = idToken
		}
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	r.ParseForm()
	token := r.FormValue("token")
	
	if token == "" {
		h.sendError(w, "invalid_request", "Token parameter required", http.StatusBadRequest)
		return
	}

	claims, err := h.auth.ValidateAccessToken(token)
	if err != nil {
		response := map[string]interface{}{"active": false}
		json.NewEncoder(w).Encode(response)
		return
	}

	dbToken, err := h.db.GetAccessToken(r.Context(), token)
	if err != nil || dbToken.Revoked {
		response := map[string]interface{}{"active": false}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := map[string]interface{}{
		"active":    true,
		"client_id": claims.ClientID,
		"user_id":   claims.UserID,
		"scope":     strings.Join(claims.Scopes, " "),
		"exp":       claims.ExpiresAt.Unix(),
		"iat":       claims.IssuedAt.Unix(),
		"sub":       claims.Subject,
		"aud":       claims.Audience,
		"iss":       claims.Issuer,
		"jti":       claims.ID,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	token := h.extractBearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.sendError(w, "invalid_request", "Bearer token required", http.StatusUnauthorized)
		return
	}

	claims, err := h.auth.ValidateAccessToken(token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		h.sendError(w, "invalid_token", "Token is invalid", http.StatusUnauthorized)
		return
	}

	dbToken, err := h.db.GetAccessToken(r.Context(), token)
	if err != nil || dbToken.Revoked {
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		h.sendError(w, "invalid_token", "Token has been revoked", http.StatusUnauthorized)
		return
	}

	if !h.oidc.HasOpenIDScope(claims.Scopes) {
		h.sendError(w, "insufficient_scope", "OpenID scope required", http.StatusForbidden)
		return
	}

	if claims.UserID == uuid.Nil {
		h.sendError(w, "invalid_token", "Token not associated with a user", http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		h.sendError(w, "server_error", "Failed to get user info", http.StatusInternalServerError)
		return
	}

	response := h.oidc.BuildUserInfoResponseEnhanced(user, claims.Scopes)
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		h.showLoginPage(w, r)
		return
	}
	
	h.handleLoginPost(w, r)
}

func (h *Handler) showLoginPage(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Server - Login</title>
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            max-width: 400px; 
            margin: 100px auto; 
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h2 { 
            text-align: center;
            color: #2c3e50;
            margin-bottom: 30px;
            font-size: 28px;
        }
        .form-group { margin-bottom: 20px; }
        label { 
            display: block; 
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        input { 
            width: 100%; 
            padding: 14px; 
            border: 2px solid #e1e8ed; 
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
        }
        button { 
            width: 100%; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 14px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            margin-top: 10px;
        }
        button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102,126,234,0.4);
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
            font-size: 48px;
        }
        @media (max-width: 480px) {
            body { margin: 20px; }
            .login-container { padding: 30px 20px; }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔐</div>
        <h2>Login</h2>
        <form method="post">
            <div class="form-group">
                <label for="username">👤 Username:</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">🔑 Password:</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>`
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, tmpl)
}

func (h *Handler) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.auth.AuthenticateUser(r.Context(), username, password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message": "Login successful",
		"user_id": user.ID,
	}
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var req struct {
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
		GrantTypes   []string `json:"grant_types"`
		IsPublic     bool     `json:"is_public"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest)
		return
	}

	clientID := uuid.New().String()
	var clientSecret string
	var hashedSecret string
	var err error

	if !req.IsPublic {
		clientSecret = uuid.New().String()
		hashedSecret, err = h.auth.HashPassword(clientSecret)
		if err != nil {
			h.sendError(w, "server_error", "Failed to generate client secret", http.StatusInternalServerError)
			return
		}
	}

	client := &db.Client{
		ClientID:     clientID,
		ClientSecret: hashedSecret,
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		GrantTypes:   req.GrantTypes,
		IsPublic:     req.IsPublic,
	}

	if err := h.db.CreateClient(r.Context(), client); err != nil {
		h.sendError(w, "server_error", "Failed to create client", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"client_id":     client.ClientID,
		"client_secret": clientSecret,
		"name":          client.Name,
		"redirect_uris": client.RedirectURIs,
		"scopes":        client.Scopes,
		"grant_types":   client.GrantTypes,
		"is_public":     client.IsPublic,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	clients, err := h.db.GetAllClients(r.Context())
	if err != nil {
		h.sendError(w, "server_error", "Failed to retrieve clients", http.StatusInternalServerError)
		return
	}
	
	publicClients := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		publicClient := map[string]interface{}{
			"client_id":     client.ClientID,
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
			"scopes":        client.Scopes,
			"grant_types":   client.GrantTypes,
			"is_public":     client.IsPublic,
			"created_at":    client.CreatedAt,
		}
		publicClients = append(publicClients, publicClient)
	}
	
	json.NewEncoder(w).Encode(publicClients)
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var req struct {
		Username string   `json:"username"`
		Email    string   `json:"email"`
		Password string   `json:"password"`
		Scopes   []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest)
		return
	}

	hashedPassword, err := h.auth.HashPassword(req.Password)
	if err != nil {
		h.sendError(w, "server_error", "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := &db.User{
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
		Scopes:   req.Scopes,
	}

	if err := h.db.CreateUser(r.Context(), user); err != nil {
		h.sendError(w, "server_error", "Failed to create user", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"scopes":   user.Scopes,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func (h *Handler) sendError(w http.ResponseWriter, errorType, description string, statusCode int) {
	w.WriteHeader(statusCode)
	response := ErrorResponse{
		Error:            errorType,
		ErrorDescription: description,
	}
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleTokenError(w http.ResponseWriter, err error) {
	switch err {
	case auth.ErrInvalidClient:
		h.sendError(w, "invalid_client", "Client authentication failed", http.StatusUnauthorized)
	case auth.ErrInvalidGrant:
		h.sendError(w, "invalid_grant", "Grant type not supported by client", http.StatusBadRequest)
	case auth.ErrInvalidScope:
		h.sendError(w, "invalid_scope", "Requested scope invalid", http.StatusBadRequest)
	case auth.ErrExpiredCode:
		h.sendError(w, "invalid_grant", "Authorization code expired", http.StatusBadRequest)
	case auth.ErrUsedCode:
		h.sendError(w, "invalid_grant", "Authorization code already used", http.StatusBadRequest)
	case auth.ErrInvalidCodeChallenge:
		h.sendError(w, "invalid_request", "Invalid code challenge", http.StatusBadRequest)
	case auth.ErrInvalidCodeVerifier:
		h.sendError(w, "invalid_request", "Invalid code verifier", http.StatusBadRequest)
	case auth.ErrCodeChallengeMismatch:
		h.sendError(w, "invalid_grant", "Code challenge verification failed", http.StatusBadRequest)
	default:
		h.sendError(w, "server_error", "Internal server error", http.StatusInternalServerError)
	}
}

func (h *Handler) validateBasicParams(clientID, redirectURI, responseType string) error {
	if clientID == "" {
		return fmt.Errorf("invalid_request: client_id is required")
	}
	if redirectURI == "" {
		return fmt.Errorf("invalid_request: redirect_uri is required")
	}
	if responseType == "" {
		return fmt.Errorf("invalid_request: response_type is required")
	}
	
	if _, err := url.Parse(redirectURI); err != nil {
		return fmt.Errorf("invalid_request: redirect_uri is not a valid URL")
	}
	
	return nil
}

func (h *Handler) validateCredentials(username, password string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}
	
	if len(username) > 255 {
		return fmt.Errorf("username too long")
	}
	if len(password) > 255 {
		return fmt.Errorf("password too long")
	}
	
	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' && r != '@' {
			return fmt.Errorf("username contains invalid characters")
		}
	}
	
	return nil
}

func (h *Handler) validateJSONInput(req interface{}) error {
	switch v := req.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if key == "" {
				return fmt.Errorf("empty key not allowed")
			}
			
			switch val := value.(type) {
			case string:
				if len(val) > 1000 {
					return fmt.Errorf("string value too long for key %s", key)
				}
			case []interface{}:
				if len(val) > 100 {
					return fmt.Errorf("array too long for key %s", key)
				}
			}
		}
	}
	return nil
}

func (h *Handler) DeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if err := r.ParseForm(); err != nil {
		h.sendError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}
	
	req := &auth.DeviceAuthorizationRequest{
		ClientID: r.FormValue("client_id"),
		Scope:    r.FormValue("scope"),
	}
	
	if req.ClientID == "" {
		h.sendError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}
	
	baseURL := "http://localhost:8080" // This should come from config
	response, err := h.auth.InitiateDeviceAuthorization(r.Context(), req, baseURL)
	if err != nil {
		h.handleTokenError(w, err)
		return
	}
	
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) DeviceVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		h.showDeviceVerificationPage(w, r)
		return
	}
	
	h.handleDeviceVerificationPost(w, r)
}

func (h *Handler) showDeviceVerificationPage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Verification</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        }
        h2 { 
            text-align: center;
            color: #2c3e50;
            margin-bottom: 30px;
        }
        .form-group { margin-bottom: 20px; }
        label { 
            display: block; 
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        input { 
            width: 100%; 
            padding: 14px; 
            border: 2px solid #e1e8ed; 
            border-radius: 8px;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        button { 
            width: 100%; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 14px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
        }
        .device-icon {
            text-align: center;
            font-size: 48px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="device-icon">📱</div>
        <h2>Device Verification</h2>
        <p>Enter the code displayed on your device to authorize the application.</p>
        
        <form method="post">
            <div class="form-group">
                <label for="user_code">Device Code:</label>
                <input type="text" id="user_code" name="user_code" value="` + template.HTMLEscapeString(userCode) + `" required placeholder="XXXX-XXXX">
            </div>
            
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Authorize Device</button>
        </form>
    </div>
</body>
</html>`
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, tmpl)
}

func (h *Handler) handleDeviceVerificationPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	
	userCode := strings.TrimSpace(strings.ToUpper(r.FormValue("user_code")))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	
	if userCode == "" || username == "" || password == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}
	
	user, err := h.auth.AuthenticateUser(r.Context(), username, password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	
	if err := h.auth.AuthorizeDeviceCode(r.Context(), userCode, user.ID); err != nil {
		http.Error(w, "Invalid device code", http.StatusBadRequest)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .success { color: #28a745; font-size: 24px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="success">✅ Device Successfully Authorized!</div>
    <p>You can now return to your device to continue.</p>
</body>
</html>`)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		h.showLogoutPage(w, r)
		return
	}
	
	h.handleLogoutPost(w, r)
}

func (h *Handler) showLogoutPage(w http.ResponseWriter, r *http.Request) {
	idTokenHint := r.URL.Query().Get("id_token_hint")
	postLogoutRedirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	state := r.URL.Query().Get("state")
	
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Server - Logout</title>
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            max-width: 500px; 
            margin: 100px auto; 
            padding: 20px;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            min-height: 100vh;
            color: white;
        }
        .logout-container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
            text-align: center;
        }
        h1 { 
            margin: 0 0 30px; 
            font-size: 32px; 
            font-weight: 300;
        }
        .logout-message {
            font-size: 18px;
            margin-bottom: 30px;
            line-height: 1.5;
        }
        .logout-form {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }
        button {
            background: rgba(255, 255, 255, 0.2);
            border: 2px solid rgba(255, 255, 255, 0.3);
            color: white;
            padding: 12px 30px;
            border-radius: 50px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }
        button:hover {
            background: rgba(255, 255, 255, 0.3);
            border-color: rgba(255, 255, 255, 0.5);
            transform: translateY(-2px);
        }
        .cancel-btn {
            background: rgba(255, 255, 255, 0.1);
        }
        .cancel-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }
    </style>
</head>
<body>
    <div class="logout-container">
        <h1>Sign Out</h1>
        <div class="logout-message">
            Are you sure you want to sign out of your account?
        </div>
        <form method="POST" class="logout-form">
            <input type="hidden" name="id_token_hint" value="{{.IDTokenHint}}">
            <input type="hidden" name="post_logout_redirect_uri" value="{{.PostLogoutRedirectURI}}">
            <input type="hidden" name="state" value="{{.State}}">
            <button type="submit" name="action" value="logout">Sign Out</button>
            <button type="button" class="cancel-btn" onclick="history.back()">Cancel</button>
        </form>
    </div>
</body>
</html>`

	data := struct {
		IDTokenHint           string
		PostLogoutRedirectURI string
		State                 string
	}{
		IDTokenHint:           idTokenHint,
		PostLogoutRedirectURI: postLogoutRedirectURI,
		State:                 state,
	}

	t, err := template.New("logout").Parse(tmpl)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

func (h *Handler) handleLogoutPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	
	action := r.FormValue("action")
	if action != "logout" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	
	_ = r.FormValue("id_token_hint")
	postLogoutRedirectURI := r.FormValue("post_logout_redirect_uri")
	state := r.FormValue("state")
	
	if postLogoutRedirectURI != "" {
		logoutURL := h.oidc.GenerateLogoutURL(postLogoutRedirectURI, state)
		if logoutURL != "" {
			http.Redirect(w, r, logoutURL, http.StatusFound)
			return
		}
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Signed Out</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .success { color: #28a745; font-size: 24px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="success">✅ Successfully Signed Out</div>
    <p>You have been signed out of your account.</p>
</body>
</html>`)
}

func (h *Handler) CheckSession(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	sessionState := r.URL.Query().Get("session_state")
	
	w.Header().Set("Content-Type", "application/json")
	
	response := map[string]interface{}{
		"session_state": sessionState,
		"client_id":     clientID,
		"status":        "unchanged",
	}
	
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) SessionIframe(w http.ResponseWriter, r *http.Request) {
	iframe := `
<!DOCTYPE html>
<html>
<head>
    <title>Session Management</title>
</head>
<body>
    <script>
        function receiveMessage(e) {
            if (e.data === "session_changed") {
                e.source.postMessage("changed", e.origin);
            } else {
                e.source.postMessage("unchanged", e.origin);
            }
        }
        window.addEventListener("message", receiveMessage, false);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	fmt.Fprint(w, iframe)
}

func (h *Handler) shouldGenerateIDToken(req *auth.TokenRequest, response *auth.TokenResponse) bool {
	if response.Scope == "" {
		return false
	}
	
	scopes := strings.Split(response.Scope, " ")
	return h.oidc.HasOpenIDScope(scopes)
}

func (h *Handler) generateIDToken(req *auth.TokenRequest, response *auth.TokenResponse) (string, error) {
	claims, err := h.auth.ValidateAccessToken(response.AccessToken)
	if err != nil {
		return "", err
	}
	
	if claims.UserID == uuid.Nil {
		return "", nil
	}
	
	user, err := h.db.GetUserByID(context.Background(), claims.UserID)
	if err != nil {
		return "", err
	}
	
	nonce := ""
	authTime := time.Now()
	ttl := 15 * time.Minute
	
	return h.oidc.GenerateIDToken(user, req.ClientID, nonce, authTime, ttl)
}

func (h *Handler) generateIDTokenForImplicit(req *auth.AuthorizeRequest, response *auth.ImplicitGrantResponse, user *db.User) (string, error) {
	authTime := time.Now()
	ttl := 15 * time.Minute
	
	return h.oidc.GenerateIDToken(user, req.ClientID, response.Nonce, authTime, ttl)
}