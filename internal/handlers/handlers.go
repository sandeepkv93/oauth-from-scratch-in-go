package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"oauth-server/internal/auth"
	"oauth-server/internal/db"
)

type Handler struct {
	auth *auth.Service
	db   db.DatabaseInterface
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func NewHandler(authService *auth.Service, database db.DatabaseInterface) *Handler {
	return &Handler{
		auth: authService,
		db:   database,
	}
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/authorize", h.Authorize).Methods("GET", "POST")
	r.HandleFunc("/token", h.Token).Methods("POST")
	r.HandleFunc("/introspect", h.Introspect).Methods("POST")
	r.HandleFunc("/userinfo", h.UserInfo).Methods("GET")
	r.HandleFunc("/revoke", h.Revoke).Methods("POST")
	r.HandleFunc("/login", h.Login).Methods("GET", "POST")
	
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

	if err := h.validateBasicParams(clientID, redirectURI, responseType); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if responseType != "code" {
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}

	client, err := h.db.GetClientByID(clientID)
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
            <input type="hidden" name="response_type" value="code">
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
		CodeChallenge       string
		CodeChallengeMethod string
	}{
		ClientID:            template.HTMLEscapeString(clientID),
		ClientName:          template.HTMLEscapeString(client.Name),
		RedirectURI:         template.HTMLEscapeString(redirectURI),
		Scope:               template.HTMLEscapeString(scope),
		Scopes:              scopes,
		State:               template.HTMLEscapeString(state),
		CodeChallenge:       template.HTMLEscapeString(codeChallenge),
		CodeChallengeMethod: template.HTMLEscapeString(codeChallengeMethod),
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
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	codeChallenge := strings.TrimSpace(r.FormValue("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(r.FormValue("code_challenge_method"))

	if err := h.validateBasicParams(clientID, redirectURI, "code"); err != nil {
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

	user, err := h.auth.AuthenticateUser(username, password)
	if err != nil {
		redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "access_denied", "Invalid credentials", state)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	scopes := []string{}
	if scope != "" {
		scopes = strings.Split(scope, " ")
	}

	code, err := h.auth.CreateAuthorizationCode(user.ID, clientID, redirectURI, scopes, codeChallenge, codeChallengeMethod)
	if err != nil {
		redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "server_error", "Failed to create authorization code", state)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	redirectURL := h.auth.CreateRedirectURL(redirectURI, code, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	r.ParseForm()
	
	req := &auth.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
		CodeVerifier: r.FormValue("code_verifier"),
	}

	var response *auth.TokenResponse
	var err error

	switch req.GrantType {
	case "authorization_code":
		response, err = h.auth.ExchangeCodeForToken(req)
	case "refresh_token":
		response, err = h.auth.RefreshAccessToken(req)
	case "client_credentials":
		response, err = h.auth.ClientCredentialsGrant(req)
	default:
		h.sendError(w, "unsupported_grant_type", "Grant type not supported", http.StatusBadRequest)
		return
	}

	if err != nil {
		h.handleTokenError(w, err)
		return
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

	dbToken, err := h.db.GetAccessToken(token)
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
		h.sendError(w, "invalid_request", "Bearer token required", http.StatusUnauthorized)
		return
	}

	claims, err := h.auth.ValidateAccessToken(token)
	if err != nil {
		h.sendError(w, "invalid_token", "Token is invalid", http.StatusUnauthorized)
		return
	}

	dbToken, err := h.db.GetAccessToken(token)
	if err != nil || dbToken.Revoked {
		h.sendError(w, "invalid_token", "Token has been revoked", http.StatusUnauthorized)
		return
	}

	if claims.UserID == uuid.Nil {
		h.sendError(w, "invalid_token", "Token not associated with a user", http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUserByID(claims.UserID)
	if err != nil {
		h.sendError(w, "server_error", "Failed to get user info", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"sub":      user.ID,
		"username": user.Username,
		"email":    user.Email,
	}

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

	user, err := h.auth.AuthenticateUser(username, password)
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

	if err := h.db.CreateClient(client); err != nil {
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
	
	clients, err := h.db.GetAllClients()
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

	if err := h.db.CreateUser(user); err != nil {
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