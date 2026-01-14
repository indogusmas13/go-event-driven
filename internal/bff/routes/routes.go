package routes

import (
	"go-event-driven/internal/bff/handler"
	"go-event-driven/pkg/auth"
	"go-event-driven/pkg/ratelimit"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App, jwtManager *auth.JWTManager, authHandler *handler.AuthHandler) {
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
}
