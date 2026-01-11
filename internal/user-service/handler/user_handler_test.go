package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"go-event-driven/internal/user-service/model"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) Register(ctx context.Context, req *model.RegisterRequest) (*model.UserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserResponse), args.Error(1)
}

func (m *MockUserService) VerifyCredentials(email, password string) (*model.VerifyCredentialsResponse, error) {
	args := m.Called(email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.VerifyCredentialsResponse), args.Error(1)
}

func (m *MockUserService) GetUserByID(id uint) (*model.UserResponse, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserResponse), args.Error(1)
}

func setupTestApp(mockService *MockUserService) *fiber.App {
	app := fiber.New()
	handler := NewUserHandler(mockService)

	app.Post("/register", handler.Register)
	app.Post("/verify-credentials", handler.VerifyCredentials)
	app.Get("/users/:id", handler.GetUser)

	return app
}

// ==================== Register Tests ====================

func TestRegister_Success(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	expectedResponse := &model.UserResponse{
		ID:        1,
		Email:     "test@example.com",
		Phone:     "1234567890",
		FirstName: "John",
		LastName:  "Doe",
		Role:      "user",
		IsActive:  true,
	}

	mockService.On("Register", mock.Anything, mock.MatchedBy(func(req *model.RegisterRequest) bool {
		return req.Email == "test@example.com" && req.Password == "password123"
	})).Return(expectedResponse, nil)

	reqBody := model.RegisterRequest{
		Email:     "test@example.com",
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

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, "User registered successfully", response["message"])

	mockService.AssertExpectations(t)
}

func TestRegister_InvalidRequestBody(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestRegister_ValidationFailed_InvalidEmail(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	reqBody := model.RegisterRequest{
		Email:     "invalid-email",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestRegister_ValidationFailed_ShortPassword(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	reqBody := model.RegisterRequest{
		Email:     "test@example.com",
		Password:  "short",
		FirstName: "John",
		LastName:  "Doe",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestRegister_ValidationFailed_MissingFields(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	reqBody := model.RegisterRequest{
		Email: "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	mockService.On("Register", mock.Anything, mock.Anything).Return(nil, errors.New("email already exists"))

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

func TestRegister_PhoneAlreadyExists(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	mockService.On("Register", mock.Anything, mock.Anything).Return(nil, errors.New("phone number already exists"))

	reqBody := model.RegisterRequest{
		Email:     "test@example.com",
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
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	mockService.On("Register", mock.Anything, mock.Anything).Return(nil, errors.New("database error"))

	reqBody := model.RegisterRequest{
		Email:     "test@example.com",
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

// ==================== VerifyCredentials Tests ====================

func TestVerifyCredentials_Success_ValidCredentials(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	expectedResponse := &model.VerifyCredentialsResponse{
		UserID:   1,
		Role:     "user",
		IsActive: true,
		Valid:    true,
	}

	mockService.On("VerifyCredentials", "test@example.com", "password123").Return(expectedResponse, nil)

	reqBody := model.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/verify-credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response model.VerifyCredentialsResponse
	json.NewDecoder(resp.Body).Decode(&response)
	assert.True(t, response.Valid)
	assert.Equal(t, uint(1), response.UserID)

	mockService.AssertExpectations(t)
}

func TestVerifyCredentials_InvalidCredentials(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	expectedResponse := &model.VerifyCredentialsResponse{
		Valid: false,
	}

	mockService.On("VerifyCredentials", "test@example.com", "wrongpassword").Return(expectedResponse, nil)

	reqBody := model.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/verify-credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response model.VerifyCredentialsResponse
	json.NewDecoder(resp.Body).Decode(&response)
	assert.False(t, response.Valid)

	mockService.AssertExpectations(t)
}

func TestVerifyCredentials_InvalidRequestBody(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	req := httptest.NewRequest("POST", "/verify-credentials", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestVerifyCredentials_ValidationFailed(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	reqBody := model.LoginRequest{
		Email:    "invalid-email",
		Password: "",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/verify-credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestVerifyCredentials_ServiceError(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	mockService.On("VerifyCredentials", "test@example.com", "password123").Return(nil, errors.New("database error"))

	reqBody := model.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/verify-credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	mockService.AssertExpectations(t)
}

// ==================== GetUser Tests ====================

func TestGetUser_Success(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	expectedResponse := &model.UserResponse{
		ID:        1,
		Email:     "test@example.com",
		Phone:     "1234567890",
		FirstName: "John",
		LastName:  "Doe",
		Role:      "user",
		IsActive:  true,
	}

	mockService.On("GetUserByID", uint(1)).Return(expectedResponse, nil)

	req := httptest.NewRequest("GET", "/users/1", nil)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response model.UserResponse
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, uint(1), response.ID)
	assert.Equal(t, "test@example.com", response.Email)

	mockService.AssertExpectations(t)
}

func TestGetUser_InvalidID(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	req := httptest.NewRequest("GET", "/users/invalid", nil)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestGetUser_NotFound(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	mockService.On("GetUserByID", uint(999)).Return(nil, errors.New("user not found"))

	req := httptest.NewRequest("GET", "/users/999", nil)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)

	mockService.AssertExpectations(t)
}

func TestGetUser_InternalError(t *testing.T) {
	mockService := new(MockUserService)
	app := setupTestApp(mockService)

	mockService.On("GetUserByID", uint(1)).Return(nil, errors.New("database error"))

	req := httptest.NewRequest("GET", "/users/1", nil)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	mockService.AssertExpectations(t)
}
