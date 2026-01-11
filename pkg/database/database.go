package database

import (
	"fmt"

	"go-event-driven/pkg/config"
	"go-event-driven/pkg/logger"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect(cfg *config.DatabaseConfig) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	logger.GetLogger().Info("Connected to database successfully")
	return db, nil
}