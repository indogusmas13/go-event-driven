package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-event-driven/internal/bff/model"
	userModel "go-event-driven/internal/user-service/model"
	"go-event-driven/pkg/auth"
	"go-event-driven/pkg/config"

	"github.com/stretchr/testify/assert"
)

func setupTestService(server *httptest.Server) AuthService {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:               "test-secret-key",
			ExpirationHours:      1,
			RefreshExpirationDays: 7,
		},
		Services: config.ServicesConfig{
			UserServiceURL: server.URL,
		},
	}

	jwtManager := auth.NewJWTManager(&cfg.JWT)
	return NewAuthService(jwtManager, cfg)
}

func TestAuthService_Login_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/verify-credentials", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		response := userModel.VerifyCredentialsResponse{
			UserID:   1,
			Role:     "user",
			IsActive: true,
			Valid:    true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	resp, err := svc.Login(req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 3600, resp.ExpiresIn)
}

func TestAuthService_Login_InvalidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := userModel.VerifyCredentialsResponse{
			Valid: false,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	resp, err := svc.Login(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid credentials")
}

func TestAuthService_Login_InactiveUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := userModel.VerifyCredentialsResponse{
			UserID:   1,
			Role:     "user",
			IsActive: false,
			Valid:    true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.LoginRequest{
		Email:    "inactive@example.com",
		Password: "password123",
	}

	resp, err := svc.Login(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "user account is inactive")
}

func TestAuthService_Login_UserServiceError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	resp, err := svc.Login(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAuthService_RefreshToken_Success(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:               "test-secret-key",
			ExpirationHours:      1,
			RefreshExpirationDays: 7,
		},
	}
	jwtManager := auth.NewJWTManager(&cfg.JWT)

	refreshToken, _ := jwtManager.GenerateRefreshToken(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/users/1", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		response := userModel.UserResponse{
			ID:       1,
			Email:    "test@example.com",
			Role:     "user",
			IsActive: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg.Services.UserServiceURL = server.URL
	svc := NewAuthService(jwtManager, cfg)

	req := &model.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	resp, err := svc.RefreshToken(req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestAuthService_RefreshToken_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.RefreshTokenRequest{
		RefreshToken: "invalid-token",
	}

	resp, err := svc.RefreshToken(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAuthService_RefreshToken_InactiveUser(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:               "test-secret-key",
			ExpirationHours:      1,
			RefreshExpirationDays: 7,
		},
	}
	jwtManager := auth.NewJWTManager(&cfg.JWT)

	refreshToken, _ := jwtManager.GenerateRefreshToken(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := userModel.UserResponse{
			ID:       1,
			Email:    "test@example.com",
			Role:     "user",
			IsActive: false,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg.Services.UserServiceURL = server.URL
	svc := NewAuthService(jwtManager, cfg)

	req := &model.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	resp, err := svc.RefreshToken(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "user account is inactive")
}

func TestAuthService_RefreshToken_UserNotFound(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:               "test-secret-key",
			ExpirationHours:      1,
			RefreshExpirationDays: 7,
		},
	}
	jwtManager := auth.NewJWTManager(&cfg.JWT)

	refreshToken, _ := jwtManager.GenerateRefreshToken(999)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg.Services.UserServiceURL = server.URL
	svc := NewAuthService(jwtManager, cfg)

	req := &model.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	resp, err := svc.RefreshToken(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAuthService_Logout_Success(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:               "test-secret-key",
			ExpirationHours:      1,
			RefreshExpirationDays: 7,
		},
	}
	jwtManager := auth.NewJWTManager(&cfg.JWT)

	refreshToken, _ := jwtManager.GenerateRefreshToken(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	cfg.Services.UserServiceURL = server.URL
	svc := NewAuthService(jwtManager, cfg)

	req := &model.LogoutRequest{
		RefreshToken: refreshToken,
	}

	err := svc.Logout(req)

	assert.NoError(t, err)
}

func TestAuthService_Logout_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.LogoutRequest{
		RefreshToken: "invalid-token",
	}

	err := svc.Logout(req)

	assert.Error(t, err)
}

func TestAuthService_Register_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/register", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		response := userModel.UserResponse{
			ID:        1,
			Email:     "newuser@example.com",
			Phone:     "1234567890",
			FirstName: "John",
			LastName:  "Doe",
			Role:      "user",
			IsActive:  true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.RegisterRequest{
		Email:     "newuser@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := svc.Register(req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, uint(1), resp.ID)
	assert.Equal(t, "newuser@example.com", resp.Email)
	assert.Equal(t, "User registered successfully", resp.Message)
}

func TestAuthService_Register_EmailExists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.RegisterRequest{
		Email:     "existing@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := svc.Register(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "email or phone already exists")
}

func TestAuthService_Register_ServiceError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	svc := setupTestService(server)

	req := &model.RegisterRequest{
		Email:     "newuser@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := svc.Register(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
}
