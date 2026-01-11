package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go-event-driven/internal/bff/handler"
	"go-event-driven/internal/bff/service"
	"go-event-driven/pkg/auth"
	"go-event-driven/pkg/config"
	"go-event-driven/pkg/logger"
	"go-event-driven/pkg/ratelimit"

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

	api := app.Group("/api/v1")

	// Register endpoint with strict rate limit (3 req/min)
	api.Post("/register", ratelimit.NewRegisterLimiter(), authHandler.Register)
	api.Post("/login", ratelimit.NewAuthLimiter(), authHandler.Login)
	
	authRoutes := api.Group("/auth")
	// Login with auth rate limit (5 req/min)
	authRoutes.Post("/login", ratelimit.NewAuthLimiter(), authHandler.Login)
	// Refresh token with moderate rate limit (10 req/min)
	authRoutes.Post("/refresh", ratelimit.NewRefreshLimiter(), authHandler.RefreshToken)
	// Logout with auth rate limit
	authRoutes.Post("/logout", ratelimit.NewAuthLimiter(), authHandler.Logout)

	protectedRoutes := api.Group("/protected")
	// General API rate limit for protected routes (100 req/min)
	protectedRoutes.Use(ratelimit.NewAPILimiter())
	protectedRoutes.Use(auth.JWTMiddleware(jwtManager))
	protectedRoutes.Get("/profile", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		email := c.Locals("email")
		role := c.Locals("role")

		return c.JSON(fiber.Map{
			"user_id": userID,
			"email":   email,
			"role":    role,
		})
	})

	adminRoutes := protectedRoutes.Group("/admin")
	adminRoutes.Use(auth.RequireRole("admin"))
	adminRoutes.Get("/dashboard", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Welcome to admin dashboard",
		})
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"service": "bff",
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
		port = 8080
	}

	log.WithField("port", port).Info("Starting BFF service")
	if err := app.Listen(fmt.Sprintf(":%d", port)); err != nil {
		log.WithError(err).Fatal("Failed to start server")
	}
}