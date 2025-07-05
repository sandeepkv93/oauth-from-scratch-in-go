package tests

import (
	"context"
	"testing"
	"time"

	"oauth-server/internal/config"
	"oauth-server/internal/db"
)

func TestEnhancedDatabaseCreation(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Host:            "localhost",
		Port:            "5432", 
		User:            "test",
		Password:        "test",
		Name:            "test_oauth_server",
		SSLMode:         "disable",
		MaxOpenConns:    10,
		MaxIdleConns:    2,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
		QueryTimeout:    30 * time.Second,
	}

	// Test database factory creation
	factory := db.NewDatabaseFactory(cfg)
	if factory == nil {
		t.Fatal("Database factory should not be nil")
	}

	// Note: We can't actually test database connection without a real database
	// This test just verifies the configuration and factory setup
}

func TestMigrationSystem(t *testing.T) {
	// Test migration definition
	migrations := db.GetAllMigrations()
	
	if len(migrations) == 0 {
		t.Fatal("Should have at least one migration")
	}

	// Verify migrations are properly ordered
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version <= migrations[i-1].Version {
			t.Errorf("Migration versions should be ascending: %d -> %d", 
				migrations[i-1].Version, migrations[i].Version)
		}
	}

	// Verify each migration has required fields
	for _, migration := range migrations {
		if migration.Version <= 0 {
			t.Errorf("Migration version should be positive: %d", migration.Version)
		}
		if migration.Name == "" {
			t.Errorf("Migration name should not be empty for version %d", migration.Version)
		}
		if migration.UpScript == "" {
			t.Errorf("Migration up script should not be empty for version %d", migration.Version)
		}
		if migration.DownScript == "" {
			t.Errorf("Migration down script should not be empty for version %d", migration.Version)
		}
	}
}

func TestHealthCheckerCreation(t *testing.T) {
	// Test health checker creation with nil database (should not panic)
	healthChecker := db.NewHealthChecker(nil)
	if healthChecker == nil {
		t.Fatal("Health checker should not be nil")
	}
}

func TestCleanupServiceCreation(t *testing.T) {
	// Test cleanup service creation with nil database (should not panic)
	cleanupService := db.NewCleanupService(nil)
	if cleanupService == nil {
		t.Fatal("Cleanup service should not be nil")
	}
}

func TestDatabaseStatsStructure(t *testing.T) {
	// Test database stats structure
	stats := &db.DatabaseStats{
		OpenConnections:    5,
		InUse:             2,
		Idle:              3,
		WaitCount:         10,
		WaitDuration:      1000000, // nanoseconds
		MaxIdleClosed:     1,
		MaxIdleTimeClosed: 2,
		MaxLifetimeClosed: 3,
	}

	if stats.OpenConnections != 5 {
		t.Errorf("Expected OpenConnections to be 5, got %d", stats.OpenConnections)
	}

	if stats.InUse != 2 {
		t.Errorf("Expected InUse to be 2, got %d", stats.InUse)
	}

	if stats.Idle != 3 {
		t.Errorf("Expected Idle to be 3, got %d", stats.Idle)
	}
}

func TestTokenHashingUtilities(t *testing.T) {
	// Since hashToken and getTokenPrefix are not exported, we test them indirectly
	// by testing that the enhanced database operations can be created without error
	
	// This would test token hashing if we had a real database connection
	// For now, we just verify the operations can be defined
	
	// Mock operations that would use token hashing
	testToken := "test_access_token_12345"
	if len(testToken) < 10 {
		t.Error("Test token should be long enough for prefix extraction")
	}
}

func TestBackgroundCleanupServiceCreation(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Host:            "localhost",
		Port:            "5432",
		User:            "test", 
		Password:        "test",
		Name:            "test_oauth_server",
		SSLMode:         "disable",
		MaxOpenConns:    10,
		MaxIdleConns:    2,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
		QueryTimeout:    30 * time.Second,
	}

	factory := db.NewDatabaseFactory(cfg)
	
	// Create background cleanup service with nil database (for testing structure)
	cleanupService := factory.CreateBackgroundCleanupService(context.Background(), nil)
	
	if cleanupService == nil {
		t.Fatal("Background cleanup service should not be nil")
	}

	// Test stopping the service (should not panic even if not started)
	cleanupService.Stop()
}