package main

import (
	"flag"
	"fmt"
	"os"

	"go-event-driven/pkg/config"
	"go-event-driven/pkg/database"
	"go-event-driven/pkg/logger"
)

func main() {
	logger.Init()
	log := logger.GetLogger()

	var (
		migrationPath = flag.String("path", "migrations", "Path to migration files")
		action        = flag.String("action", "up", "Migration action: up, down, create")
		name          = flag.String("name", "", "Migration name (for create action)")
		steps         = flag.Int("steps", 0, "Number of migration steps (for down action)")
	)
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.WithError(err).Fatal("Failed to load configuration")
	}

	switch *action {
	case "up":
		if err := database.RunMigrations(&cfg.Database, *migrationPath); err != nil {
			log.WithError(err).Fatal("Failed to run migrations")
		}
		log.Info("Migrations completed successfully")

	case "create":
		if *name == "" {
			log.Fatal("Migration name is required for create action")
		}
		if err := database.CreateMigration(*migrationPath, *name); err != nil {
			log.WithError(err).Fatal("Failed to create migration")
		}
		log.WithField("name", *name).Info("Migration files created")

	case "down":
		log.WithField("steps", *steps).Info("Down migration not implemented in this simple version")
		fmt.Println("Down migration requires manual implementation")
		os.Exit(1)

	default:
		log.WithField("action", *action).Fatal("Unknown action. Use: up, down, or create")
	}
}