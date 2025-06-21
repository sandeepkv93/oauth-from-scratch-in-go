package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

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
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

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
<html>
<head>
    <title>Authorize Application</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .client-info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .scopes { background: #e9ecef; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <h2>Authorize Application</h2>
    <div class="client-info">
        <h3>{{.ClientName}}</h3>
        <p>This application is requesting access to your account.</p>
        {{if .Scopes}}
        <div class="scopes">
            <strong>Requested permissions:</strong>
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
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        
        <button type="submit" name="action" value="authorize">Authorize</button>
        <button type="submit" name="action" value="deny">Deny</button>
    </form>
</body>
</html>`

	t, _ := template.New("authorize").Parse(tmpl)
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
		ClientID:            clientID,
		ClientName:          client.Name,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Scopes:              scopes,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	
	t.Execute(w, data)
}

func (h *Handler) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	
	action := r.FormValue("action")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	username := r.FormValue("username")
	password := r.FormValue("password")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	if action == "deny" {
		redirectURL := h.auth.CreateErrorRedirectURL(redirectURI, "access_denied", "User denied the request", state)
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
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; background: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h2>Login</h2>
    <form method="post">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit">Login</button>
    </form>
</body>
</html>`
	
	w.Header().Set("Content-Type", "text/html")
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
	var err error

	if !req.IsPublic {
		clientSecret, err = h.auth.HashPassword(uuid.New().String())
		if err != nil {
			h.sendError(w, "server_error", "Failed to generate client secret", http.StatusInternalServerError)
			return
		}
	}

	client := &db.Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
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
		"client_secret": client.ClientSecret,
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
	
	clients := []map[string]interface{}{
		{
			"message": "Client listing not implemented yet",
		},
	}
	
	json.NewEncoder(w).Encode(clients)
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