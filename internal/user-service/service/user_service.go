package service

import (
	"context"
	"errors"
	"fmt"

	"go-event-driven/internal/user-service/model"
	"go-event-driven/internal/user-service/repository"
	"go-event-driven/pkg/kafka"
	"go-event-driven/pkg/logger"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserService interface {
	Register(ctx context.Context, req *model.RegisterRequest) (*model.UserResponse, error)
	VerifyCredentials(email, password string) (*model.VerifyCredentialsResponse, error)
	GetUserByID(id uint) (*model.UserResponse, error)
}

type userService struct {
	repo     repository.UserRepository
	producer *kafka.Producer
}

func NewUserService(repo repository.UserRepository, producer *kafka.Producer) UserService {
	return &userService{
		repo:     repo,
		producer: producer,
	}
}

func (s *userService) Register(ctx context.Context, req *model.RegisterRequest) (*model.UserResponse, error) {
	log := logger.GetLogger()

	emailExists, err := s.repo.ExistsByEmail(req.Email)
	if err != nil {
		log.WithError(err).Error("Failed to check email existence")
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}
	if emailExists {
		return nil, errors.New("email already exists")
	}

	if req.Phone != "" {
		phoneExists, err := s.repo.ExistsByPhone(req.Phone)
		if err != nil {
			log.WithError(err).Error("Failed to check phone existence")
			return nil, fmt.Errorf("failed to check phone existence: %w", err)
		}
		if phoneExists {
			return nil, errors.New("phone number already exists")
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.WithError(err).Error("Failed to hash password")
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &model.User{
		Email:     req.Email,
		Phone:     req.Phone,
		Password:  string(hashedPassword),
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Role:      "user",
		IsActive:  true,
	}

	if err := s.repo.Create(user); err != nil {
		log.WithError(err).Error("Failed to create user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	event := kafka.Event{
		Type: "UserRegistered",
		Payload: kafka.UserRegisteredEvent{
			UserID:    user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role,
		},
	}

	if err := s.producer.PublishEvent(ctx, "user-events", event); err != nil {
		log.WithError(err).Error("Failed to publish UserRegistered event")
	}

	response := &model.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Phone:     user.Phone,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
	}

	log.WithField("user_id", user.ID).Info("User registered successfully")
	return response, nil
}

func (s *userService) VerifyCredentials(email, password string) (*model.VerifyCredentialsResponse, error) {
	log := logger.GetLogger()

	user, err := s.repo.GetByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &model.VerifyCredentialsResponse{Valid: false}, nil
		}
		log.WithError(err).Error("Failed to get user by email")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		log.WithField("email", email).Info("Invalid password")
		return &model.VerifyCredentialsResponse{Valid: false}, nil
	}

	response := &model.VerifyCredentialsResponse{
		UserID:   user.ID,
		Role:     user.Role,
		IsActive: user.IsActive,
		Valid:    true,
	}

	log.WithField("user_id", user.ID).Info("Credentials verified successfully")
	return response, nil
}

func (s *userService) GetUserByID(id uint) (*model.UserResponse, error) {
	log := logger.GetLogger()

	user, err := s.repo.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		log.WithError(err).WithField("user_id", id).Error("Failed to get user by ID")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	response := &model.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Phone:     user.Phone,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
	}

	return response, nil
}