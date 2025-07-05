package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// HealthChecker provides database health monitoring
type HealthChecker struct {
	db *sql.DB
}

func NewHealthChecker(db *sql.DB) *HealthChecker {
	return &HealthChecker{db: db}
}

// HealthStatus represents the health status of the database
type HealthStatus struct {
	Status      string            `json:"status"`
	Timestamp   time.Time         `json:"timestamp"`
	Latency     time.Duration     `json:"latency"`
	Connections *DatabaseStats    `json:"connections,omitempty"`
	Checks      map[string]string `json:"checks"`
	Error       string            `json:"error,omitempty"`
}

// CheckHealth performs comprehensive health checks
func (h *HealthChecker) CheckHealth(ctx context.Context) *HealthStatus {
	start := time.Now()
	status := &HealthStatus{
		Timestamp: start,
		Checks:    make(map[string]string),
	}
	
	// Check basic connectivity
	if err := h.checkConnectivity(ctx); err != nil {
		status.Status = "unhealthy"
		status.Error = err.Error()
		status.Checks["connectivity"] = "failed"
		status.Latency = time.Since(start)
		return status
	}
	status.Checks["connectivity"] = "ok"
	
	// Check read operations
	if err := h.checkReadOperations(ctx); err != nil {
		status.Status = "degraded"
		status.Checks["read_operations"] = "failed"
	} else {
		status.Checks["read_operations"] = "ok"
	}
	
	// Check write operations
	if err := h.checkWriteOperations(ctx); err != nil {
		status.Status = "degraded"
		status.Checks["write_operations"] = "failed"
	} else {
		status.Checks["write_operations"] = "ok"
	}
	
	// Get connection pool stats
	stats := h.db.Stats()
	status.Connections = &DatabaseStats{
		OpenConnections:    stats.OpenConnections,
		InUse:             stats.InUse,
		Idle:              stats.Idle,
		WaitCount:         stats.WaitCount,
		WaitDuration:      int64(stats.WaitDuration),
		MaxIdleClosed:     stats.MaxIdleClosed,
		MaxIdleTimeClosed: stats.MaxIdleTimeClosed,
		MaxLifetimeClosed: stats.MaxLifetimeClosed,
	}
	
	// Check connection pool health
	if stats.OpenConnections > 0 {
		status.Checks["connection_pool"] = "ok"
	} else {
		status.Checks["connection_pool"] = "no_connections"
	}
	
	// Overall status
	if status.Status == "" {
		status.Status = "healthy"
	}
	
	status.Latency = time.Since(start)
	return status
}

func (h *HealthChecker) checkConnectivity(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	return h.db.PingContext(ctx)
}

func (h *HealthChecker) checkReadOperations(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	query := `SELECT COUNT(*) FROM schema_migrations`
	var count int
	return h.db.QueryRowContext(ctx, query).Scan(&count)
}

func (h *HealthChecker) checkWriteOperations(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	// Test with a simple transaction
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	
	// Create a temporary table and insert/delete data
	_, err = tx.ExecContext(ctx, `CREATE TEMP TABLE health_check (id INTEGER)`)
	if err != nil {
		return err
	}
	
	_, err = tx.ExecContext(ctx, `INSERT INTO health_check (id) VALUES (1)`)
	if err != nil {
		return err
	}
	
	_, err = tx.ExecContext(ctx, `DELETE FROM health_check WHERE id = 1`)
	if err != nil {
		return err
	}
	
	return tx.Commit()
}

// CleanupService provides database maintenance operations
type CleanupService struct {
	db *EnhancedDatabase
}

func NewCleanupService(db *EnhancedDatabase) *CleanupService {
	return &CleanupService{db: db}
}

// CleanupExpiredRecords removes expired tokens and codes
func (c *CleanupService) CleanupExpiredRecords(ctx context.Context) (*CleanupResult, error) {
	start := time.Now()
	result := &CleanupResult{
		StartTime: start,
	}
	
	// Clean expired authorization codes
	codesResult, err := c.db.db.ExecContext(ctx, `DELETE FROM authorization_codes WHERE expires_at < NOW()`)
	if err != nil {
		return result, fmt.Errorf("failed to clean authorization codes: %w", err)
	}
	result.AuthorizationCodes, _ = codesResult.RowsAffected()
	
	// Clean expired device codes
	deviceResult, err := c.db.db.ExecContext(ctx, `DELETE FROM device_codes WHERE expires_at < NOW()`)
	if err != nil {
		return result, fmt.Errorf("failed to clean device codes: %w", err)
	}
	result.DeviceCodes, _ = deviceResult.RowsAffected()
	
	// Clean expired refresh tokens
	refreshResult, err := c.db.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < NOW()`)
	if err != nil {
		return result, fmt.Errorf("failed to clean refresh tokens: %w", err)
	}
	result.RefreshTokens, _ = refreshResult.RowsAffected()
	
	// Clean expired access tokens
	accessResult, err := c.db.db.ExecContext(ctx, `DELETE FROM access_tokens WHERE expires_at < NOW()`)
	if err != nil {
		return result, fmt.Errorf("failed to clean access tokens: %w", err)
	}
	result.AccessTokens, _ = accessResult.RowsAffected()
	
	result.Duration = time.Since(start)
	result.TotalRecords = result.AuthorizationCodes + result.DeviceCodes + result.RefreshTokens + result.AccessTokens
	
	return result, nil
}

// CleanupOldRevoked removes old revoked tokens for retention policy
func (c *CleanupService) CleanupOldRevoked(ctx context.Context, retentionDays int) (*CleanupResult, error) {
	start := time.Now()
	result := &CleanupResult{
		StartTime: start,
	}
	
	retentionDate := time.Now().AddDate(0, 0, -retentionDays)
	
	// Clean old revoked access tokens
	accessResult, err := c.db.db.ExecContext(ctx, 
		`DELETE FROM access_tokens WHERE revoked = true AND revoked_at < $1`, 
		retentionDate)
	if err != nil {
		return result, fmt.Errorf("failed to clean old revoked access tokens: %w", err)
	}
	result.AccessTokens, _ = accessResult.RowsAffected()
	
	// Clean old revoked refresh tokens
	refreshResult, err := c.db.db.ExecContext(ctx, 
		`DELETE FROM refresh_tokens WHERE revoked = true AND revoked_at < $1`, 
		retentionDate)
	if err != nil {
		return result, fmt.Errorf("failed to clean old revoked refresh tokens: %w", err)
	}
	result.RefreshTokens, _ = refreshResult.RowsAffected()
	
	result.Duration = time.Since(start)
	result.TotalRecords = result.AccessTokens + result.RefreshTokens
	
	return result, nil
}

// CleanupResult represents the result of a cleanup operation
type CleanupResult struct {
	StartTime          time.Time     `json:"start_time"`
	Duration           time.Duration `json:"duration"`
	AuthorizationCodes int64         `json:"authorization_codes_cleaned"`
	DeviceCodes        int64         `json:"device_codes_cleaned"`
	AccessTokens       int64         `json:"access_tokens_cleaned"`
	RefreshTokens      int64         `json:"refresh_tokens_cleaned"`
	TotalRecords       int64         `json:"total_records_cleaned"`
}

// GetTableStats returns statistics about table sizes
func (c *CleanupService) GetTableStats(ctx context.Context) (map[string]TableStats, error) {
	stats := make(map[string]TableStats)
	
	tables := []string{"users", "clients", "authorization_codes", "access_tokens", "refresh_tokens", "device_codes"}
	
	for _, table := range tables {
		query := fmt.Sprintf(`
			SELECT 
				COUNT(*) as total_rows,
				pg_total_relation_size('%s') as total_size,
				pg_relation_size('%s') as table_size
			FROM %s
		`, table, table, table)
		
		var tableStats TableStats
		err := c.db.db.QueryRowContext(ctx, query).Scan(
			&tableStats.TotalRows,
			&tableStats.TotalSize,
			&tableStats.TableSize,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get stats for table %s: %w", table, err)
		}
		
		tableStats.TableName = table
		stats[table] = tableStats
	}
	
	return stats, nil
}

// TableStats represents statistics for a database table
type TableStats struct {
	TableName string `json:"table_name"`
	TotalRows int64  `json:"total_rows"`
	TotalSize int64  `json:"total_size_bytes"`
	TableSize int64  `json:"table_size_bytes"`
}