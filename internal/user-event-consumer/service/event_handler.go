package service

import (
	"encoding/json"
	"fmt"

	"go-event-driven/pkg/kafka"
	"go-event-driven/pkg/logger"
)

type UserEventHandler struct {}

func NewUserEventHandler() *UserEventHandler {
	return &UserEventHandler{}
}

func (h *UserEventHandler) HandleEvent(event kafka.Event) error {
	switch event.Type {
	case "UserRegistered":
		return h.handleUserRegistered(event.Payload)
	default:
		logger.GetLogger().WithField("event_type", event.Type).Warn("Unknown event type")
		return nil
	}
}

func (h *UserEventHandler) handleUserRegistered(payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	var userRegistered kafka.UserRegisteredEvent
	if err := json.Unmarshal(payloadBytes, &userRegistered); err != nil {
		return fmt.Errorf("failed to unmarshal UserRegisteredEvent: %w", err)
	}

	logger.GetLogger().WithFields(map[string]interface{}{
		"user_id":    userRegistered.UserID,
		"email":      userRegistered.Email,
		"first_name": userRegistered.FirstName,
		"last_name":  userRegistered.LastName,
		"role":       userRegistered.Role,
	}).Info("Processing user registration event")

	if err := h.processUserRegistration(userRegistered); err != nil {
		return fmt.Errorf("failed to process user registration: %w", err)
	}

	logger.GetLogger().WithField("user_id", userRegistered.UserID).Info("User registration event processed successfully")
	return nil
}

func (h *UserEventHandler) processUserRegistration(user kafka.UserRegisteredEvent) error {
	logger.GetLogger().WithField("user_id", user.UserID).Info("Welcome new user!")
	
	return nil
}