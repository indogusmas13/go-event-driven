package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"go-event-driven/internal/bff/model"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(req *model.LoginRequest) (*model.LoginResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.LoginResponse), args.Error(1)
}

func (m *MockAuthService) RefreshToken(req *model.RefreshTokenRequest) (*model.LoginResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.LoginResponse), args.Error(1)
}

func (m *MockAuthService) Logout(req *model.LogoutRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *MockAuthService) Register(req *model.RegisterRequest) (*model.RegisterResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RegisterResponse), args.Error(1)
}

func setupTestApp(mockService *MockAuthService) *fiber.App {
	app := fiber.New()
	handler := NewAuthHandler(mockService)

	app.Post("/login", handler.Login)
	app.Post("/refresh", handler.RefreshToken)
	app.Post("/logout", handler.Logout)
	app.Post("/register", handler.Register)

	return app
}

func TestLogin_Success(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	expectedResponse := &model.LoginResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	mockService.On("Login", mock.MatchedBy(func(req *model.LoginRequest) bool {
		return req.Email == "test@example.com" && req.Password == "password123"
	})).Return(expectedResponse, nil)

	reqBody := model.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response model.LoginResponse
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, expectedResponse.AccessToken, response.AccessToken)
	assert.Equal(t, expectedResponse.RefreshToken, response.RefreshToken)

	mockService.AssertExpectations(t)
}

func TestLogin_InvalidRequestBody(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	req := httptest.NewRequest("POST", "/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestLogin_ValidationFailed(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	reqBody := model.LoginRequest{
		Email:    "invalid-email",
		Password: "",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	mockService.On("Login", mock.Anything).Return(nil, errors.New("invalid credentials"))

	reqBody := model.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	mockService.AssertExpectations(t)
}

func TestLogin_InactiveAccount(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	mockService.On("Login", mock.Anything).Return(nil, errors.New("user account is inactive"))

	reqBody := model.LoginRequest{
		Email:    "inactive@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)

	mockService.AssertExpectations(t)
}

func TestRefreshToken_Success(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	expectedResponse := &model.LoginResponse{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	mockService.On("RefreshToken", mock.MatchedBy(func(req *model.RefreshTokenRequest) bool {
		return req.RefreshToken == "valid-refresh-token"
	})).Return(expectedResponse, nil)

	reqBody := model.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response model.LoginResponse
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, expectedResponse.AccessToken, response.AccessToken)

	mockService.AssertExpectations(t)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	mockService.On("RefreshToken", mock.Anything).Return(nil, errors.New("invalid token"))

	reqBody := model.RefreshTokenRequest{
		RefreshToken: "invalid-token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	mockService.AssertExpectations(t)
}

func TestRefreshToken_InactiveAccount(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	mockService.On("RefreshToken", mock.Anything).Return(nil, errors.New("user account is inactive"))

	reqBody := model.RefreshTokenRequest{
		RefreshToken: "valid-token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)

	mockService.AssertExpectations(t)
}

func TestLogout_Success(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	mockService.On("Logout", mock.MatchedBy(func(req *model.LogoutRequest) bool {
		return req.RefreshToken == "valid-refresh-token"
	})).Return(nil)

	reqBody := model.LogoutRequest{
		RefreshToken: "valid-refresh-token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockService.AssertExpectations(t)
}

func TestLogout_InvalidToken(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	mockService.On("Logout", mock.Anything).Return(errors.New("invalid token"))

	reqBody := model.LogoutRequest{
		RefreshToken: "invalid-token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	mockService.AssertExpectations(t)
}

func TestRegister_Success(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	expectedResponse := &model.RegisterResponse{
		ID:        1,
		Email:     "newuser@example.com",
		Phone:     "1234567890",
		FirstName: "John",
		LastName:  "Doe",
		Message:   "User registered successfully",
	}

	mockService.On("Register", mock.MatchedBy(func(req *model.RegisterRequest) bool {
		return req.Email == "newuser@example.com" && req.Password == "password123"
	})).Return(expectedResponse, nil)

	reqBody := model.RegisterRequest{
		Email:     "newuser@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

	var response model.RegisterResponse
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, expectedResponse.Email, response.Email)
	assert.Equal(t, expectedResponse.ID, response.ID)

	mockService.AssertExpectations(t)
}

func TestRegister_ValidationFailed(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	reqBody := model.RegisterRequest{
		Email:     "invalid-email",
		Password:  "short",
		FirstName: "J",
		LastName:  "D",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	mockService.On("Register", mock.Anything).Return(nil, errors.New("email or phone already exists"))

	reqBody := model.RegisterRequest{
		Email:     "existing@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusConflict, resp.StatusCode)

	mockService.AssertExpectations(t)
}

func TestRegister_InternalError(t *testing.T) {
	mockService := new(MockAuthService)
	app := setupTestApp(mockService)

	mockService.On("Register", mock.Anything).Return(nil, errors.New("internal error"))

	reqBody := model.RegisterRequest{
		Email:     "newuser@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	mockService.AssertExpectations(t)
}
