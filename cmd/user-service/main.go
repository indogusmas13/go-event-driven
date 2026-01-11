package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go-event-driven/internal/user-service/handler"
	"go-event-driven/internal/user-service/repository"
	"go-event-driven/internal/user-service/service"
	"go-event-driven/pkg/config"
	"go-event-driven/pkg/database"
	"go-event-driven/pkg/kafka"
	"go-event-driven/pkg/logger"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
	logger.Init()
	log := logger.GetLogger()

	cfg, err := config.Load()
	if err != nil {
		log.WithError(err).Fatal("Failed to load configuration")
	}

	db, err := database.Connect(&cfg.Database)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
	}

	producer := kafka.NewProducer(cfg.Kafka.Brokers)
	defer producer.Close()

	userRepo := repository.NewUserRepository(db)
	userService := service.NewUserService(userRepo, producer)
	userHandler := handler.NewUserHandler(userService)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.WithError(err).Error("Unhandled error")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal server error",
			})
		},
	})

	app.Use(recover.New())
	app.Use(cors.New())

	api := app.Group("/api/v1")
	api.Post("/register", userHandler.Register)
	api.Post("/verify-credentials", userHandler.VerifyCredentials)
	api.Get("/users/:id", userHandler.GetUser)

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
			"service": "user-service",
		})
	})

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Info("Shutdown signal received")
		cancel()
		app.Shutdown()
	}()

	port := cfg.Server.Port
	if port == 0 {
		port = 8081
	}

	log.WithField("port", port).Info("Starting user service")
	if err := app.Listen(fmt.Sprintf(":%d", port)); err != nil {
		log.WithError(err).Fatal("Failed to start server")
	}
}