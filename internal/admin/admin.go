package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/auth"
	"oauth-server/internal/db"
	"oauth-server/internal/scopes"
)

type Service struct {
	db          db.DatabaseInterface
	auth        *auth.Service
	scopes      *scopes.Service
	templates   *template.Template
	startTime   time.Time
	version     string
}

type Config struct {
	Version string
}

type DashboardData struct {
	Title      string
	ActivePage string
	Stats      *Stats
	RecentActivity []*ActivityLog
	ServerInfo *ServerInfo
	Charts     *Charts
	Flash      *FlashMessage
}

type Stats struct {
	TotalClients   int
	TotalUsers     int
	ActiveTokens   int
	TotalScopes    int
}

type ActivityLog struct {
	Timestamp time.Time
	Event     string
	ClientID  string
	UserID    string
	Status    string
}

type ServerInfo struct {
	Version          string
	Uptime           string
	StartTime        time.Time
	GoVersion        string
	DatabaseHealthy  bool
}

type Charts struct {
	GrantTypes     *ChartData
	TokenIssuance  *ChartData
}

type ChartData struct {
	Labels []string
	Data   []int
}

type FlashMessage struct {
	Type    string // success, error, warning, info
	Message string
}

type ClientsPageData struct {
	Title      string
	ActivePage string
	Clients    []*db.Client
	Pagination *Pagination
	Flash      *FlashMessage
}

type Pagination struct {
	CurrentPage int
	TotalPages  int
	TotalItems  int
	Pages       []int
}

type ClientFormData struct {
	Title                 string
	ActivePage            string
	Client                *db.Client
	AvailableGrantTypes   []string
	AvailableResponseTypes []string
	AvailableScopes       []*db.Scope
	Flash                 *FlashMessage
}

func NewService(database db.DatabaseInterface, authService *auth.Service, scopeService *scopes.Service, config *Config) *Service {
	s := &Service{
		db:        database,
		auth:      authService,
		scopes:    scopeService,
		startTime: time.Now(),
		version:   config.Version,
	}

	// Load templates
	s.loadTemplates()

	return s
}

func (s *Service) loadTemplates() {
	funcMap := template.FuncMap{
		"contains": func(slice []string, item string) bool {
			for _, s := range slice {
				if s == item {
					return true
				}
			}
			return false
		},
		"join": func(slice []string, sep string) string {
			return strings.Join(slice, sep)
		},
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"now": func() time.Time {
			return time.Now()
		},
		"eq": func(a, b interface{}) bool {
			return a == b
		},
	}

	s.templates = template.Must(template.New("").Funcs(funcMap).ParseGlob("web/templates/admin/*.html"))
}

func (s *Service) RegisterRoutes(r *mux.Router) {
	admin := r.PathPrefix("/admin").Subrouter()
	
	// Dashboard
	admin.HandleFunc("/", s.Dashboard).Methods("GET")
	admin.HandleFunc("", s.Dashboard).Methods("GET")
	
	// Client management
	admin.HandleFunc("/clients", s.ListClients).Methods("GET")
	admin.HandleFunc("/clients/new", s.NewClient).Methods("GET")
	admin.HandleFunc("/clients/new", s.CreateClient).Methods("POST")
	admin.HandleFunc("/clients/{client_id}", s.ViewClient).Methods("GET")
	admin.HandleFunc("/clients/{client_id}/edit", s.EditClient).Methods("GET")
	admin.HandleFunc("/clients/{client_id}/edit", s.UpdateClient).Methods("POST")
	
	// API endpoints
	api := admin.PathPrefix("/api").Subrouter()
	api.HandleFunc("/clients", s.APIListClients).Methods("GET")
	api.HandleFunc("/clients", s.APICreateClient).Methods("POST")
	api.HandleFunc("/clients/{client_id}", s.APIDeleteClient).Methods("DELETE")
	api.HandleFunc("/clients/{client_id}/regenerate-secret", s.APIRegenerateSecret).Methods("POST")
	api.HandleFunc("/clients/export", s.APIExportClients).Methods("GET")
	api.HandleFunc("/cleanup/tokens", s.APICleanupTokens).Methods("POST")
}

func (s *Service) Dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Get statistics
	stats, err := s.getStats(ctx)
	if err != nil {
		s.renderError(w, "Failed to load dashboard statistics", err)
		return
	}
	
	// Get recent activity (mock data for now)
	recentActivity := s.getRecentActivity(ctx)
	
	// Get server info
	serverInfo := s.getServerInfo(ctx)
	
	// Get chart data
	charts := s.getChartData(ctx)
	
	data := &DashboardData{
		Title:          "Dashboard",
		ActivePage:     "dashboard",
		Stats:          stats,
		RecentActivity: recentActivity,
		ServerInfo:     serverInfo,
		Charts:         charts,
	}
	
	s.renderTemplate(w, "admin/dashboard.html", data)
}

func (s *Service) ListClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Parse pagination parameters
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	
	limit := 20
	offset := (page - 1) * limit
	
	// Get clients with pagination
	clients, err := s.db.GetAllClients(ctx)
	if err != nil {
		s.renderError(w, "Failed to load clients", err)
		return
	}
	
	// Apply pagination (simple implementation)
	totalClients := len(clients)
	totalPages := (totalClients + limit - 1) / limit
	
	start := offset
	end := offset + limit
	if start > totalClients {
		start = totalClients
	}
	if end > totalClients {
		end = totalClients
	}
	
	paginatedClients := clients[start:end]
	
	// Generate page numbers
	pages := make([]int, 0)
	for i := 1; i <= totalPages; i++ {
		pages = append(pages, i)
	}
	
	pagination := &Pagination{
		CurrentPage: page,
		TotalPages:  totalPages,
		TotalItems:  totalClients,
		Pages:       pages,
	}
	
	data := &ClientsPageData{
		Title:      "OAuth Clients",
		ActivePage: "clients",
		Clients:    paginatedClients,
		Pagination: pagination,
	}
	
	s.renderTemplate(w, "admin/clients.html", data)
}

func (s *Service) NewClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	data := &ClientFormData{
		Title:      "Create New Client",
		ActivePage: "clients",
		Client:     &db.Client{},
	}
	
	// Load form options
	if err := s.loadFormOptions(ctx, data); err != nil {
		s.renderError(w, "Failed to load form options", err)
		return
	}
	
	s.renderTemplate(w, "admin/client_form.html", data)
}

func (s *Service) CreateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	if err := r.ParseForm(); err != nil {
		s.renderError(w, "Invalid form data", err)
		return
	}
	
	client := &db.Client{
		Name:            r.FormValue("name"),
		RedirectURIs:    r.Form["redirect_uris"],
		GrantTypes:      r.Form["grant_types"],
		ResponseTypes:   r.Form["response_types"],
		Scopes:          r.Form["scopes"],
		IsPublic:        r.FormValue("is_public") == "true",
	}
	
	// Set optional fields
	if clientURI := r.FormValue("client_uri"); clientURI != "" {
		client.ClientURI = &clientURI
	}
	if logoURI := r.FormValue("logo_uri"); logoURI != "" {
		client.LogoURI = &logoURI
	}
	if tosURI := r.FormValue("tos_uri"); tosURI != "" {
		client.TosURI = &tosURI
	}
	if policyURI := r.FormValue("policy_uri"); policyURI != "" {
		client.PolicyURI = &policyURI
	}
	if jwksURI := r.FormValue("jwks_uri"); jwksURI != "" {
		client.JwksURI = &jwksURI
	}
	if contacts := r.FormValue("contacts"); contacts != "" {
		client.ContactEmails = strings.Split(contacts, ",")
		for i := range client.ContactEmails {
			client.ContactEmails[i] = strings.TrimSpace(client.ContactEmails[i])
		}
	}
	
	// Generate client credentials
	if err := s.generateClientCredentials(client); err != nil {
		s.renderError(w, "Failed to generate client credentials", err)
		return
	}
	
	// Create client
	if err := s.db.CreateClient(ctx, client); err != nil {
		s.renderError(w, "Failed to create client", err)
		return
	}
	
	// Redirect to client details
	http.Redirect(w, r, fmt.Sprintf("/admin/clients/%s", client.ClientID), http.StatusSeeOther)
}

func (s *Service) ViewClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["client_id"]
	
	ctx := r.Context()
	client, err := s.db.GetClientByID(ctx, clientID)
	if err != nil {
		s.renderError(w, "Client not found", err)
		return
	}
	
	data := &ClientFormData{
		Title:      fmt.Sprintf("Client: %s", client.Name),
		ActivePage: "clients",
		Client:     client,
	}
	
	// Load form options
	if err := s.loadFormOptions(ctx, data); err != nil {
		s.renderError(w, "Failed to load form options", err)
		return
	}
	
	s.renderTemplate(w, "admin/client_form.html", data)
}

func (s *Service) EditClient(w http.ResponseWriter, r *http.Request) {
	s.ViewClient(w, r) // Same as view for now
}

func (s *Service) UpdateClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["client_id"]
	
	ctx := r.Context()
	client, err := s.db.GetClientByID(ctx, clientID)
	if err != nil {
		s.renderError(w, "Client not found", err)
		return
	}
	
	if err := r.ParseForm(); err != nil {
		s.renderError(w, "Invalid form data", err)
		return
	}
	
	// Update client fields
	client.Name = r.FormValue("name")
	client.RedirectURIs = r.Form["redirect_uris"]
	client.GrantTypes = r.Form["grant_types"]
	client.ResponseTypes = r.Form["response_types"]
	client.Scopes = r.Form["scopes"]
	client.IsPublic = r.FormValue("is_public") == "true"
	client.UpdatedAt = time.Now()
	
	// Update optional fields
	if clientURI := r.FormValue("client_uri"); clientURI != "" {
		client.ClientURI = &clientURI
	} else {
		client.ClientURI = nil
	}
	
	// Save client
	if err := s.db.UpdateClient(ctx, client); err != nil {
		s.renderError(w, "Failed to update client", err)
		return
	}
	
	// Redirect back to client
	http.Redirect(w, r, fmt.Sprintf("/admin/clients/%s", client.ClientID), http.StatusSeeOther)
}

// API endpoints

func (s *Service) APIListClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clients, err := s.db.GetAllClients(ctx)
	if err != nil {
		s.sendJSONError(w, "Failed to load clients", http.StatusInternalServerError)
		return
	}
	
	s.sendJSON(w, clients)
}

func (s *Service) APICreateClient(w http.ResponseWriter, r *http.Request) {
	// Implementation for API client creation
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Service) APIDeleteClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["client_id"]
	
	ctx := r.Context()
	if err := s.db.DeleteClient(ctx, clientID); err != nil {
		s.sendJSONError(w, "Failed to delete client", http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func (s *Service) APIRegenerateSecret(w http.ResponseWriter, r *http.Request) {
	// Implementation for regenerating client secret
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Service) APIExportClients(w http.ResponseWriter, r *http.Request) {
	// Implementation for exporting clients
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Service) APICleanupTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Clean up expired tokens
	if err := s.db.CleanupExpiredTokens(ctx); err != nil {
		s.sendJSONError(w, "Failed to cleanup tokens", http.StatusInternalServerError)
		return
	}
	
	// Clean up expired codes
	if err := s.db.CleanupExpiredCodes(ctx); err != nil {
		s.sendJSONError(w, "Failed to cleanup codes", http.StatusInternalServerError)
		return
	}
	
	response := map[string]interface{}{
		"success": true,
		"message": "Expired tokens and codes cleaned up successfully",
		"count":   0, // Would need to implement count tracking
	}
	
	s.sendJSON(w, response)
}

// Helper methods

func (s *Service) getStats(ctx context.Context) (*Stats, error) {
	clients, err := s.db.GetAllClients(ctx)
	if err != nil {
		return nil, err
	}
	
	scopes, _ := s.db.GetAllScopes(ctx)
	
	return &Stats{
		TotalClients: len(clients),
		TotalUsers:   0, // Would need to implement user counting
		ActiveTokens: 0, // Would need to implement token counting
		TotalScopes:  len(scopes),
	}, nil
}

func (s *Service) getRecentActivity(ctx context.Context) []*ActivityLog {
	// Mock data - in a real implementation, this would come from audit logs
	return []*ActivityLog{
		{
			Timestamp: time.Now().Add(-5 * time.Minute),
			Event:     "Token issued",
			ClientID:  "test-client",
			UserID:    "user123",
			Status:    "success",
		},
		{
			Timestamp: time.Now().Add(-10 * time.Minute),
			Event:     "Client created",
			ClientID:  "new-client",
			UserID:    "admin",
			Status:    "success",
		},
	}
}

func (s *Service) getServerInfo(ctx context.Context) *ServerInfo {
	uptime := time.Since(s.startTime)
	
	// Check database health
	dbHealthy := true
	if err := s.db.Ping(ctx); err != nil {
		dbHealthy = false
	}
	
	return &ServerInfo{
		Version:         s.version,
		Uptime:          uptime.String(),
		StartTime:       s.startTime,
		GoVersion:       runtime.Version(),
		DatabaseHealthy: dbHealthy,
	}
}

func (s *Service) getChartData(ctx context.Context) *Charts {
	// Mock chart data - in a real implementation, this would come from metrics
	return &Charts{
		GrantTypes: &ChartData{
			Labels: []string{"authorization_code", "client_credentials", "refresh_token", "password"},
			Data:   []int{65, 20, 10, 5},
		},
		TokenIssuance: &ChartData{
			Labels: []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
			Data:   []int{12, 19, 3, 5, 2, 3, 10},
		},
	}
}

func (s *Service) loadFormOptions(ctx context.Context, data *ClientFormData) error {
	data.AvailableGrantTypes = []string{
		"authorization_code",
		"implicit",
		"refresh_token",
		"client_credentials",
		"password",
		"urn:ietf:params:oauth:grant-type:device_code",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	}
	
	data.AvailableResponseTypes = []string{
		"code",
		"token",
		"id_token",
		"code id_token",
		"code token",
		"code token id_token",
	}
	
	scopes, err := s.db.GetAllScopes(ctx)
	if err != nil {
		return err
	}
	data.AvailableScopes = scopes
	
	return nil
}

func (s *Service) renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, tmpl, data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func (s *Service) renderError(w http.ResponseWriter, message string, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	
	errorMsg := message
	if err != nil {
		errorMsg += ": " + err.Error()
	}
	
	fmt.Fprintf(w, `
	<html>
	<head><title>Error</title></head>
	<body>
		<h1>Error</h1>
		<p>%s</p>
		<a href="/admin">Back to Admin</a>
	</body>
	</html>
	`, errorMsg)
}

func (s *Service) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Service) sendJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (s *Service) generateClientCredentials(client *db.Client) error {
	// Generate client ID
	clientID, err := s.generateRandomString(16)
	if err != nil {
		return fmt.Errorf("failed to generate client ID: %w", err)
	}
	client.ClientID = clientID
	
	// Generate client secret for confidential clients
	if !client.IsPublic {
		clientSecret, err := s.generateRandomString(32)
		if err != nil {
			return fmt.Errorf("failed to generate client secret: %w", err)
		}
		
		// Hash the secret before storing
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash client secret: %w", err)
		}
		client.ClientSecret = string(hashedSecret)
	}
	
	// Set timestamps
	now := time.Now()
	client.CreatedAt = now
	client.UpdatedAt = now
	
	// Generate UUID
	client.ID = uuid.New()
	
	return nil
}

func (s *Service) generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}