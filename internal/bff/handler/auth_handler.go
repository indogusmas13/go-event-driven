package handler

import (
	"go-event-driven/internal/bff/model"
	"go-event-driven/internal/bff/service"
	"go-event-driven/pkg/logger"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	authService service.AuthService
	validator   *validator.Validate
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validator:   validator.New(),
	}
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req model.LoginRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		log := logger.GetLogger()
		log.WithError(err).Error("Login failed")

		if err.Error() == "invalid credentials" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid email or password",
			})
		}

		if err.Error() == "user account is inactive" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Account is inactive",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Login failed",
		})
	}

	return c.JSON(response)
}

func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req model.RefreshTokenRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	response, err := h.authService.RefreshToken(&req)
	if err != nil {
		log := logger.GetLogger()
		log.WithError(err).Error("Token refresh failed")

		if err.Error() == "user account is inactive" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Account is inactive",
			})
		}

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid refresh token",
		})
	}

	return c.JSON(response)
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	var req model.LogoutRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	if err := h.authService.Logout(&req); err != nil {
		log := logger.GetLogger()
		log.WithError(err).Error("Logout failed")

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid refresh token",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req model.RegisterRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	response, err := h.authService.Register(&req)
	if err != nil {
		log := logger.GetLogger()
		log.WithError(err).Error("Registration failed")

		if err.Error() == "email or phone already exists" {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Email or phone already exists",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Registration failed",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}