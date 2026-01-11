package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go-event-driven/internal/bff/model"
	userModel "go-event-driven/internal/user-service/model"
	"go-event-driven/pkg/auth"
	"go-event-driven/pkg/config"
	"go-event-driven/pkg/logger"
)

type AuthService interface {
	Login(req *model.LoginRequest) (*model.LoginResponse, error)
	RefreshToken(req *model.RefreshTokenRequest) (*model.LoginResponse, error)
	Logout(req *model.LogoutRequest) error
	Register(req *model.RegisterRequest) (*model.RegisterResponse, error)
}

type authService struct {
	jwtManager *auth.JWTManager
	config     *config.Config
	httpClient *http.Client
}

func NewAuthService(jwtManager *auth.JWTManager, config *config.Config) AuthService {
	return &authService{
		jwtManager: jwtManager,
		config:     config,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *authService) Login(req *model.LoginRequest) (*model.LoginResponse, error) {
	log := logger.GetLogger()

	credentialsReq := &userModel.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	jsonData, err := json.Marshal(credentialsReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := s.httpClient.Post(
		s.config.Services.UserServiceURL+"/api/v1/verify-credentials",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		log.WithError(err).Error("Failed to call user service")
		return nil, fmt.Errorf("failed to verify credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.WithField("status", resp.StatusCode).WithField("body", string(body)).Error("User service returned error")
		return nil, fmt.Errorf("failed to verify credentials: status %d", resp.StatusCode)
	}

	var credentialsResp userModel.VerifyCredentialsResponse
	if err := json.NewDecoder(resp.Body).Decode(&credentialsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !credentialsResp.Valid {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !credentialsResp.IsActive {
		return nil, fmt.Errorf("user account is inactive")
	}

	accessToken, err := s.jwtManager.GenerateToken(credentialsResp.UserID, req.Email, credentialsResp.Role)
	if err != nil {
		log.WithError(err).Error("Failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(credentialsResp.UserID)
	if err != nil {
		log.WithError(err).Error("Failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	response := &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.config.JWT.ExpirationHours * 3600,
	}

	log.WithField("user_id", credentialsResp.UserID).Info("User logged in successfully")
	return response, nil
}

func (s *authService) RefreshToken(req *model.RefreshTokenRequest) (*model.LoginResponse, error) {
	log := logger.GetLogger()

	userID, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		log.WithError(err).Error("Invalid refresh token")
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	userResp, err := s.httpClient.Get(
		fmt.Sprintf("%s/api/v1/users/%d", s.config.Services.UserServiceURL, userID),
	)
	if err != nil {
		log.WithError(err).Error("Failed to get user from user service")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user not found or service error")
	}

	var user userModel.UserResponse
	if err := json.NewDecoder(userResp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user response: %w", err)
	}

	if !user.IsActive {
		return nil, fmt.Errorf("user account is inactive")
	}

	accessToken, err := s.jwtManager.GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		log.WithError(err).Error("Failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		log.WithError(err).Error("Failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	response := &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.config.JWT.ExpirationHours * 3600,
	}

	log.WithField("user_id", user.ID).Info("Token refreshed successfully")
	return response, nil
}

func (s *authService) Logout(req *model.LogoutRequest) error {
	log := logger.GetLogger()

	_, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		log.WithError(err).Error("Invalid refresh token during logout")
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	log.Info("User logged out successfully")
	return nil
}

func (s *authService) Register(req *model.RegisterRequest) (*model.RegisterResponse, error) {
	log := logger.GetLogger()

	registerReq := &userModel.RegisterRequest{
		Email:     req.Email,
		Phone:     req.Phone,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	jsonData, err := json.Marshal(registerReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := s.httpClient.Post(
		s.config.Services.UserServiceURL+"/api/v1/register",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		log.WithError(err).Error("Failed to call user service for registration")
		return nil, fmt.Errorf("failed to register user: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("email or phone already exists")
	}

	if resp.StatusCode != http.StatusCreated {
		log.WithField("status", resp.StatusCode).WithField("body", string(body)).Error("User service returned error")
		return nil, fmt.Errorf("failed to register user: status %d", resp.StatusCode)
	}

	var userResp userModel.UserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	response := &model.RegisterResponse{
		ID:        userResp.ID,
		Email:     userResp.Email,
		Phone:     userResp.Phone,
		FirstName: userResp.FirstName,
		LastName:  userResp.LastName,
		Message:   "User registered successfully",
	}

	log.WithField("user_id", userResp.ID).Info("User registered successfully via BFF")
	return response, nil
}