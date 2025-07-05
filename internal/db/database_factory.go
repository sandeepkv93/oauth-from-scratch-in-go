package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"oauth-server/internal/config"
)

// DatabaseFactory creates and configures database instances
type DatabaseFactory struct {
	config *config.DatabaseConfig
}

func NewDatabaseFactory(config *config.DatabaseConfig) *DatabaseFactory {
	return &DatabaseFactory{config: config}
}

// CreateEnhancedDatabase creates a new enhanced database instance with all optimizations
func (f *DatabaseFactory) CreateEnhancedDatabase(ctx context.Context) (*EnhancedDatabase, error) {
	log.Printf("Initializing enhanced database with connection pooling...")
	log.Printf("Connection pool settings: MaxOpen=%d, MaxIdle=%d, MaxLifetime=%s, MaxIdleTime=%s",
		f.config.MaxOpenConns, f.config.MaxIdleConns, f.config.ConnMaxLifetime, f.config.ConnMaxIdleTime)
	
	// Create enhanced database
	db, err := NewEnhancedDatabase(f.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create enhanced database: %w", err)
	}
	
	// Run migrations
	if err := f.runMigrations(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}
	
	// Verify health
	healthChecker := NewHealthChecker(db.db)
	health := healthChecker.CheckHealth(ctx)
	if health.Status != "healthy" {
		db.Close()
		return nil, fmt.Errorf("database health check failed: %s", health.Error)
	}
	
	log.Printf("Enhanced database initialized successfully (latency: %s)", health.Latency)
	
	return db, nil
}

// runMigrations applies all pending migrations
func (f *DatabaseFactory) runMigrations(ctx context.Context, db *EnhancedDatabase) error {
	migrationManager := NewMigrationManager(db.db)
	
	// Initialize migration table
	if err := migrationManager.InitializeMigrationTable(ctx); err != nil {
		return fmt.Errorf("failed to initialize migration table: %w", err)
	}
	
	// Get all migrations
	allMigrations := GetAllMigrations()
	
	// Get pending migrations
	pending, err := migrationManager.GetPendingMigrations(ctx, allMigrations)
	if err != nil {
		return fmt.Errorf("failed to get pending migrations: %w", err)
	}
	
	if len(pending) == 0 {
		log.Printf("No pending migrations")
		return nil
	}
	
	log.Printf("Applying %d pending migrations...", len(pending))
	for _, migration := range pending {
		log.Printf("Applying migration %d: %s", migration.Version, migration.Name)
		if err := migrationManager.ApplyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
	}
	
	log.Printf("All migrations applied successfully")
	return nil
}

// CreateBackgroundCleanupService creates and starts a background cleanup service
func (f *DatabaseFactory) CreateBackgroundCleanupService(ctx context.Context, db *EnhancedDatabase) *BackgroundCleanupService {
	return &BackgroundCleanupService{
		cleanupService: NewCleanupService(db),
		interval:       30 * time.Minute, // Run cleanup every 30 minutes
		retentionDays:  30,               // Keep revoked tokens for 30 days
	}
}

// BackgroundCleanupService runs periodic database cleanup
type BackgroundCleanupService struct {
	cleanupService *CleanupService
	interval       time.Duration
	retentionDays  int
	stopCh         chan struct{}
}

// Start begins the background cleanup process
func (s *BackgroundCleanupService) Start(ctx context.Context) {
	s.stopCh = make(chan struct{})
	ticker := time.NewTicker(s.interval)
	
	go func() {
		defer ticker.Stop()
		
		// Run initial cleanup
		s.runCleanup(ctx)
		
		for {
			select {
			case <-ticker.C:
				s.runCleanup(ctx)
			case <-s.stopCh:
				log.Printf("Background cleanup service stopped")
				return
			case <-ctx.Done():
				log.Printf("Background cleanup service stopped due to context cancellation")
				return
			}
		}
	}()
	
	log.Printf("Background cleanup service started (interval: %s)", s.interval)
}

// Stop halts the background cleanup process
func (s *BackgroundCleanupService) Stop() {
	if s.stopCh != nil {
		close(s.stopCh)
	}
}

func (s *BackgroundCleanupService) runCleanup(ctx context.Context) {
	start := time.Now()
	
	// Clean expired records
	result, err := s.cleanupService.CleanupExpiredRecords(ctx)
	if err != nil {
		log.Printf("Failed to cleanup expired records: %v", err)
		return
	}
	
	// Clean old revoked tokens
	revokedResult, err := s.cleanupService.CleanupOldRevoked(ctx, s.retentionDays)
	if err != nil {
		log.Printf("Failed to cleanup old revoked tokens: %v", err)
		return
	}
	
	totalCleaned := result.TotalRecords + revokedResult.TotalRecords
	if totalCleaned > 0 {
		log.Printf("Database cleanup completed: %d expired records, %d old revoked tokens (took %s)",
			result.TotalRecords, revokedResult.TotalRecords, time.Since(start))
	}
}

// DatabaseService provides a high-level interface for database operations
type DatabaseService struct {
	db             *EnhancedDatabase
	cleanupService *BackgroundCleanupService
	healthChecker  *HealthChecker
}

func NewDatabaseService(config *config.DatabaseConfig) (*DatabaseService, error) {
	ctx := context.Background()
	
	factory := NewDatabaseFactory(config)
	
	// Create enhanced database
	db, err := factory.CreateEnhancedDatabase(ctx)
	if err != nil {
		return nil, err
	}
	
	// Create services
	cleanupService := factory.CreateBackgroundCleanupService(ctx, db)
	healthChecker := NewHealthChecker(db.db)
	
	service := &DatabaseService{
		db:             db,
		cleanupService: cleanupService,
		healthChecker:  healthChecker,
	}
	
	// Start background cleanup
	cleanupService.Start(ctx)
	
	return service, nil
}

// GetDatabase returns the enhanced database instance
func (s *DatabaseService) GetDatabase() *EnhancedDatabase {
	return s.db
}

// GetHealthStatus returns the current database health status
func (s *DatabaseService) GetHealthStatus(ctx context.Context) *HealthStatus {
	return s.healthChecker.CheckHealth(ctx)
}

// GetStats returns database statistics
func (s *DatabaseService) GetStats(ctx context.Context) (*DatabaseStats, error) {
	return s.db.GetDatabaseStats(ctx)
}

// Close gracefully shuts down the database service
func (s *DatabaseService) Close() error {
	log.Printf("Shutting down database service...")
	
	// Stop cleanup service
	if s.cleanupService != nil {
		s.cleanupService.Stop()
	}
	
	// Close database
	if s.db != nil {
		return s.db.Close()
	}
	
	return nil
}

// RunCleanupNow manually triggers a cleanup operation
func (s *DatabaseService) RunCleanupNow(ctx context.Context) (*CleanupResult, error) {
	return s.cleanupService.cleanupService.CleanupExpiredRecords(ctx)
}

// GetTableStats returns statistics for all tables
func (s *DatabaseService) GetTableStats(ctx context.Context) (map[string]TableStats, error) {
	return s.cleanupService.cleanupService.GetTableStats(ctx)
}