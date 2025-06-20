package monitoring

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync"
	"time"
)

type Metrics struct {
	mu                     sync.RWMutex
	StartTime              time.Time            `json:"start_time"`
	TotalRequests          int64                `json:"total_requests"`
	ActiveRequests         int64                `json:"active_requests"`
	TokensIssued           int64                `json:"tokens_issued"`
	TokensRevoked          int64                `json:"tokens_revoked"`
	AuthorizationCodes     int64                `json:"authorization_codes_issued"`
	FailedAuthentications  int64                `json:"failed_authentications"`
	RequestsByEndpoint     map[string]int64     `json:"requests_by_endpoint"`
	ResponseTimeHistogram  map[string][]float64 `json:"response_time_histogram"`
	ErrorCounts           map[string]int64     `json:"error_counts"`
	ClientRequestCounts   map[string]int64     `json:"client_request_counts"`
}

type Service struct {
	metrics *Metrics
}

func NewService() *Service {
	return &Service{
		metrics: &Metrics{
			StartTime:             time.Now(),
			RequestsByEndpoint:    make(map[string]int64),
			ResponseTimeHistogram: make(map[string][]float64),
			ErrorCounts:          make(map[string]int64),
			ClientRequestCounts:  make(map[string]int64),
		},
	}
}

func (s *Service) IncrementRequests() {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.TotalRequests++
}

func (s *Service) IncrementActiveRequests() {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.ActiveRequests++
}

func (s *Service) DecrementActiveRequests() {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.ActiveRequests--
}

func (s *Service) IncrementTokensIssued() {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.TokensIssued++
}

func (s *Service) IncrementTokensRevoked() {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.TokensRevoked++
}

func (s *Service) IncrementAuthorizationCodes() {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.AuthorizationCodes++
}

func (s *Service) IncrementFailedAuthentications() {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.FailedAuthentications++
}

func (s *Service) RecordEndpointRequest(endpoint string) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.RequestsByEndpoint[endpoint]++
}

func (s *Service) RecordResponseTime(endpoint string, duration time.Duration) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	
	durationMs := float64(duration.Nanoseconds()) / 1e6
	s.metrics.ResponseTimeHistogram[endpoint] = append(
		s.metrics.ResponseTimeHistogram[endpoint], 
		durationMs,
	)
	
	if len(s.metrics.ResponseTimeHistogram[endpoint]) > 1000 {
		s.metrics.ResponseTimeHistogram[endpoint] = s.metrics.ResponseTimeHistogram[endpoint][100:]
	}
}

func (s *Service) RecordError(errorType string) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.ErrorCounts[errorType]++
}

func (s *Service) RecordClientRequest(clientID string) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.ClientRequestCounts[clientID]++
}

func (s *Service) GetMetrics() *Metrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	
	metricsCopy := &Metrics{
		StartTime:             s.metrics.StartTime,
		TotalRequests:         s.metrics.TotalRequests,
		ActiveRequests:        s.metrics.ActiveRequests,
		TokensIssued:          s.metrics.TokensIssued,
		TokensRevoked:         s.metrics.TokensRevoked,
		AuthorizationCodes:    s.metrics.AuthorizationCodes,
		FailedAuthentications: s.metrics.FailedAuthentications,
		RequestsByEndpoint:    make(map[string]int64),
		ResponseTimeHistogram: make(map[string][]float64),
		ErrorCounts:          make(map[string]int64),
		ClientRequestCounts:  make(map[string]int64),
	}
	
	for k, v := range s.metrics.RequestsByEndpoint {
		metricsCopy.RequestsByEndpoint[k] = v
	}
	
	for k, v := range s.metrics.ResponseTimeHistogram {
		metricsCopy.ResponseTimeHistogram[k] = append([]float64{}, v...)
	}
	
	for k, v := range s.metrics.ErrorCounts {
		metricsCopy.ErrorCounts[k] = v
	}
	
	for k, v := range s.metrics.ClientRequestCounts {
		metricsCopy.ClientRequestCounts[k] = v
	}
	
	return metricsCopy
}

func (s *Service) GetSystemMetrics() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)
	
	return map[string]interface{}{
		"uptime_seconds":     time.Since(s.metrics.StartTime).Seconds(),
		"memory_alloc_mb":    float64(memStats.Alloc) / 1024 / 1024,
		"memory_sys_mb":      float64(memStats.Sys) / 1024 / 1024,
		"memory_heap_mb":     float64(memStats.HeapAlloc) / 1024 / 1024,
		"gc_runs":           memStats.NumGC,
		"goroutines":        runtime.NumGoroutine(),
		"cpu_cores":         runtime.NumCPU(),
		"go_version":        runtime.Version(),
	}
}

func (s *Service) ServeMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.GetMetrics()
	systemMetrics := s.GetSystemMetrics()
	
	response := map[string]interface{}{
		"oauth_metrics":  metrics,
		"system_metrics": systemMetrics,
		"timestamp":      time.Now().Unix(),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Service) ServeHealthCheck(w http.ResponseWriter, r *http.Request) {
	metrics := s.GetMetrics()
	systemMetrics := s.GetSystemMetrics()
	
	status := "healthy"
	if metrics.ActiveRequests > 1000 {
		status = "degraded"
	}
	
	memAllocMB := systemMetrics["memory_alloc_mb"].(float64)
	if memAllocMB > 500 {
		status = "degraded"
	}
	
	response := map[string]interface{}{
		"status":       status,
		"timestamp":    time.Now().Unix(),
		"uptime":       systemMetrics["uptime_seconds"],
		"version":      "1.0.0",
		"build":        "development",
	}
	
	statusCode := http.StatusOK
	if status == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}