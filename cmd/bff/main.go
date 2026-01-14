package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go-event-driven/internal/bff/handler"
	"go-event-driven/internal/bff/routes"
	"go-event-driven/internal/bff/service"
	"go-event-driven/pkg/auth"
	"go-event-driven/pkg/config"
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

	jwtManager := auth.NewJWTManager(&cfg.JWT)
	authService := service.NewAuthService(jwtManager, cfg)
	authHandler := handler.NewAuthHandler(authService)


	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.WithError(err).Error("Unhandled error")
			code := fiber.StatusInternalServerError
			message := "Internal server error"
			
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
				message = e.Message
			}
			
			log.WithError(err).WithField("status", code).Error(message)
			
			c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSONCharsetUTF8)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal server error",
			})
		},
	})

	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization",
	}))

	routes.SetupRoutes(app, jwtManager, authHandler)

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
		port = 8080
	}

	log.WithField("port", port).Info("Starting BFF service")
	if err := app.Listen(fmt.Sprintf(":%d", port)); err != nil {
		log.WithError(err).Fatal("Failed to start server")
	}
}