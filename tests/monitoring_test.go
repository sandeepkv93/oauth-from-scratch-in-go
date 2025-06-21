package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"oauth-server/internal/monitoring"
)

func TestMonitoringServiceCreation(t *testing.T) {
	service := monitoring.NewService()
	if service == nil {
		t.Fatal("Monitoring service should not be nil")
	}
}

func TestMetricsInitialization(t *testing.T) {
	service := monitoring.NewService()
	metrics := service.GetMetrics()

	if metrics.TotalRequests != 0 {
		t.Errorf("Expected initial total requests 0, got %d", metrics.TotalRequests)
	}

	if metrics.ActiveRequests != 0 {
		t.Errorf("Expected initial active requests 0, got %d", metrics.ActiveRequests)
	}

	if metrics.TokensIssued != 0 {
		t.Errorf("Expected initial tokens issued 0, got %d", metrics.TokensIssued)
	}

	if metrics.StartTime.IsZero() {
		t.Error("Start time should be set")
	}

	if metrics.RequestsByEndpoint == nil {
		t.Error("RequestsByEndpoint should be initialized")
	}

	if metrics.ResponseTimeHistogram == nil {
		t.Error("ResponseTimeHistogram should be initialized")
	}

	if metrics.ErrorCounts == nil {
		t.Error("ErrorCounts should be initialized")
	}

	if metrics.ClientRequestCounts == nil {
		t.Error("ClientRequestCounts should be initialized")
	}
}

func TestIncrementRequests(t *testing.T) {
	service := monitoring.NewService()

	service.IncrementRequests()
	service.IncrementRequests()

	metrics := service.GetMetrics()
	if metrics.TotalRequests != 2 {
		t.Errorf("Expected total requests 2, got %d", metrics.TotalRequests)
	}
}

func TestActiveRequestsTracking(t *testing.T) {
	service := monitoring.NewService()

	service.IncrementActiveRequests()
	service.IncrementActiveRequests()

	metrics := service.GetMetrics()
	if metrics.ActiveRequests != 2 {
		t.Errorf("Expected active requests 2, got %d", metrics.ActiveRequests)
	}

	service.DecrementActiveRequests()
	metrics = service.GetMetrics()
	if metrics.ActiveRequests != 1 {
		t.Errorf("Expected active requests 1, got %d", metrics.ActiveRequests)
	}
}

func TestTokenMetrics(t *testing.T) {
	service := monitoring.NewService()

	service.IncrementTokensIssued()
	service.IncrementTokensIssued()
	service.IncrementTokensRevoked()

	metrics := service.GetMetrics()
	if metrics.TokensIssued != 2 {
		t.Errorf("Expected tokens issued 2, got %d", metrics.TokensIssued)
	}

	if metrics.TokensRevoked != 1 {
		t.Errorf("Expected tokens revoked 1, got %d", metrics.TokensRevoked)
	}
}

func TestAuthorizationCodeMetrics(t *testing.T) {
	service := monitoring.NewService()

	service.IncrementAuthorizationCodes()
	service.IncrementAuthorizationCodes()
	service.IncrementAuthorizationCodes()

	metrics := service.GetMetrics()
	if metrics.AuthorizationCodes != 3 {
		t.Errorf("Expected authorization codes 3, got %d", metrics.AuthorizationCodes)
	}
}

func TestFailedAuthenticationMetrics(t *testing.T) {
	service := monitoring.NewService()

	service.IncrementFailedAuthentications()
	service.IncrementFailedAuthentications()

	metrics := service.GetMetrics()
	if metrics.FailedAuthentications != 2 {
		t.Errorf("Expected failed authentications 2, got %d", metrics.FailedAuthentications)
	}
}

func TestEndpointRequestTracking(t *testing.T) {
	service := monitoring.NewService()

	service.RecordEndpointRequest("/token")
	service.RecordEndpointRequest("/token")
	service.RecordEndpointRequest("/authorize")

	metrics := service.GetMetrics()
	if metrics.RequestsByEndpoint["/token"] != 2 {
		t.Errorf("Expected /token requests 2, got %d", metrics.RequestsByEndpoint["/token"])
	}

	if metrics.RequestsByEndpoint["/authorize"] != 1 {
		t.Errorf("Expected /authorize requests 1, got %d", metrics.RequestsByEndpoint["/authorize"])
	}
}

func TestResponseTimeTracking(t *testing.T) {
	service := monitoring.NewService()

	duration1 := 100 * time.Millisecond
	duration2 := 200 * time.Millisecond

	service.RecordResponseTime("/token", duration1)
	service.RecordResponseTime("/token", duration2)

	metrics := service.GetMetrics()
	responseTimes := metrics.ResponseTimeHistogram["/token"]

	if len(responseTimes) != 2 {
		t.Errorf("Expected 2 response times, got %d", len(responseTimes))
	}

	expectedTime1 := 100.0
	expectedTime2 := 200.0

	if responseTimes[0] != expectedTime1 {
		t.Errorf("Expected first response time %f, got %f", expectedTime1, responseTimes[0])
	}

	if responseTimes[1] != expectedTime2 {
		t.Errorf("Expected second response time %f, got %f", expectedTime2, responseTimes[1])
	}
}

func TestResponseTimeHistogramLimit(t *testing.T) {
	service := monitoring.NewService()

	for i := 0; i < 1500; i++ {
		service.RecordResponseTime("/test", time.Millisecond)
	}

	metrics := service.GetMetrics()
	responseTimes := metrics.ResponseTimeHistogram["/test"]

	if len(responseTimes) > 1000 {
		t.Errorf("Response time histogram should be limited to 1000 entries, got %d", len(responseTimes))
	}
}

func TestErrorTracking(t *testing.T) {
	service := monitoring.NewService()

	service.RecordError("invalid_client")
	service.RecordError("invalid_client")
	service.RecordError("invalid_grant")

	metrics := service.GetMetrics()
	if metrics.ErrorCounts["invalid_client"] != 2 {
		t.Errorf("Expected invalid_client errors 2, got %d", metrics.ErrorCounts["invalid_client"])
	}

	if metrics.ErrorCounts["invalid_grant"] != 1 {
		t.Errorf("Expected invalid_grant errors 1, got %d", metrics.ErrorCounts["invalid_grant"])
	}
}

func TestClientRequestTracking(t *testing.T) {
	service := monitoring.NewService()

	service.RecordClientRequest("client1")
	service.RecordClientRequest("client1")
	service.RecordClientRequest("client2")

	metrics := service.GetMetrics()
	if metrics.ClientRequestCounts["client1"] != 2 {
		t.Errorf("Expected client1 requests 2, got %d", metrics.ClientRequestCounts["client1"])
	}

	if metrics.ClientRequestCounts["client2"] != 1 {
		t.Errorf("Expected client2 requests 1, got %d", metrics.ClientRequestCounts["client2"])
	}
}

func TestGetSystemMetrics(t *testing.T) {
	service := monitoring.NewService()
	systemMetrics := service.GetSystemMetrics()

	expectedFields := []string{
		"uptime_seconds",
		"memory_alloc_mb",
		"memory_sys_mb",
		"memory_heap_mb",
		"gc_runs",
		"goroutines",
		"cpu_cores",
		"go_version",
	}

	for _, field := range expectedFields {
		if _, exists := systemMetrics[field]; !exists {
			t.Errorf("Expected system metric field %s", field)
		}
	}

	if uptime, ok := systemMetrics["uptime_seconds"].(float64); !ok || uptime < 0 {
		t.Errorf("Uptime should be a non-negative float64, got %v", systemMetrics["uptime_seconds"])
	}

	if goroutines, ok := systemMetrics["goroutines"].(int); !ok || goroutines <= 0 {
		t.Errorf("Goroutines should be a positive int, got %v", systemMetrics["goroutines"])
	}

	if cpuCores, ok := systemMetrics["cpu_cores"].(int); !ok || cpuCores <= 0 {
		t.Errorf("CPU cores should be a positive int, got %v", systemMetrics["cpu_cores"])
	}
}

func TestServeMetrics(t *testing.T) {
	service := monitoring.NewService()

	service.IncrementRequests()
	service.IncrementTokensIssued()

	req, err := http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.ServeMetrics)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %d", status)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if _, exists := response["oauth_metrics"]; !exists {
		t.Error("Response should contain oauth_metrics")
	}

	if _, exists := response["system_metrics"]; !exists {
		t.Error("Response should contain system_metrics")
	}

	if _, exists := response["timestamp"]; !exists {
		t.Error("Response should contain timestamp")
	}
}

func TestServeHealthCheck(t *testing.T) {
	service := monitoring.NewService()

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.ServeHealthCheck)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %d", status)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	expectedFields := []string{"status", "timestamp", "uptime", "version", "build"}
	for _, field := range expectedFields {
		if _, exists := response[field]; !exists {
			t.Errorf("Health response should contain %s", field)
		}
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status healthy, got %v", response["status"])
	}
}

func TestHealthCheckDegraded(t *testing.T) {
	service := monitoring.NewService()

	for i := 0; i < 1001; i++ {
		service.IncrementActiveRequests()
	}

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.ServeHealthCheck)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", status)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "degraded" {
		t.Errorf("Expected status degraded, got %v", response["status"])
	}
}

func TestMetricsCopy(t *testing.T) {
	service := monitoring.NewService()

	service.IncrementRequests()
	service.RecordEndpointRequest("/test")

	metrics1 := service.GetMetrics()
	metrics2 := service.GetMetrics()

	if &metrics1.RequestsByEndpoint == &metrics2.RequestsByEndpoint {
		t.Error("GetMetrics should return a copy, not the same map reference")
	}

	metrics1.TotalRequests = 999
	if metrics2.TotalRequests == 999 {
		t.Error("Modifying returned metrics should not affect the original")
	}
}

func TestConcurrentMetricsAccess(t *testing.T) {
	service := monitoring.NewService()

	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			service.IncrementRequests()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			service.GetMetrics()
		}
		done <- true
	}()

	<-done
	<-done

	metrics := service.GetMetrics()
	if metrics.TotalRequests != 100 {
		t.Errorf("Expected total requests 100, got %d", metrics.TotalRequests)
	}
}