package handler

import (
	"strconv"

	"go-event-driven/internal/user-service/model"
	"go-event-driven/internal/user-service/service"
	"go-event-driven/pkg/logger"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type UserHandler struct {
	service   service.UserService
	validator *validator.Validate
}

func NewUserHandler(service service.UserService) *UserHandler {
	return &UserHandler{
		service:   service,
		validator: validator.New(),
	}
}

func (h *UserHandler) Register(c *fiber.Ctx) error {
	var req model.RegisterRequest
	
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Validation failed",
			"details": err.Error(),
		})
	}

	user, err := h.service.Register(c.Context(), &req)
	if err != nil {
		logger.GetLogger().WithError(err).Error("Failed to register user")
		
		if err.Error() == "email already exists" || err.Error() == "phone number already exists" {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to register user",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User registered successfully",
		"user":    user,
	})
}

func (h *UserHandler) VerifyCredentials(c *fiber.Ctx) error {
	var req model.LoginRequest
	
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Validation failed",
			"details": err.Error(),
		})
	}

	result, err := h.service.VerifyCredentials(req.Email, req.Password)
	if err != nil {
		logger.GetLogger().WithError(err).Error("Failed to verify credentials")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to verify credentials",
		})
	}

	return c.JSON(result)
}

func (h *UserHandler) GetUser(c *fiber.Ctx) error {
	userIDStr := c.Params("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	user, err := h.service.GetUserByID(uint(userID))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("user_id", userID).Error("Failed to get user")
		
		if err.Error() == "user not found" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get user",
		})
	}

	return c.JSON(user)
}