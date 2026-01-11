package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"go-event-driven/pkg/config"
	"go-event-driven/pkg/logger"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func RunMigrations(cfg *config.DatabaseConfig, migrationPath string) error {
	log := logger.GetLogger()

	db, err := sql.Open("pgx", cfg.DSN())
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create database driver: %w", err)
	}

	var absPath string
	// var errr error

	if migrationPath == "" {
		// Try to auto-find migrations directory
		absPath, err = FindMigrationsPath()
		if err != nil {
			return fmt.Errorf("migrations directory not found, tried common locations")
		}
		log.WithField("auto_detected_path", absPath).Info("Auto-detected migrations directory")
	} else {
		// Use provided path
		absPath, err = filepath.Abs(migrationPath)
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %w", err)
		}

		// Check if migrations directory exists
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return fmt.Errorf("migrations directory not found: %s", absPath)
		}
	}

	sourceURL := fmt.Sprintf("file://%s", absPath)
	log.WithField("migration_path", sourceURL).Info("Using migration path")
	
	m, err := migrate.NewWithDatabaseInstance(
		sourceURL,
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer m.Close()

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	log.WithField("current_version", version).WithField("dirty", dirty).Info("Current migration status")

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	newVersion, _, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get new migration version: %w", err)
	}

	log.WithField("new_version", newVersion).Info("Migration completed successfully")
	return nil
}

func CreateMigration(migrationPath, name string) error {
	if migrationPath == "" {
		migrationPath = "migrations"
	}

	timestamp := "000001"
	
	upFile := filepath.Join(migrationPath, fmt.Sprintf("%s_%s.up.sql", timestamp, name))
	downFile := filepath.Join(migrationPath, fmt.Sprintf("%s_%s.down.sql", timestamp, name))

	log := logger.GetLogger()
	log.WithField("up_file", upFile).WithField("down_file", downFile).Info("Migration files would be created at these paths")

	return nil
}