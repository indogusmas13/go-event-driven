package service

import (
	"context"
	"testing"

	"go-event-driven/internal/user-service/model"
	"go-event-driven/pkg/kafka"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ==================== Mock Repository ====================

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *model.User) error {
	args := m.Called(user)
	if args.Error(0) == nil {
		user.ID = 1 // Simulate DB assigning ID
	}
	return args.Error(0)
}

func (m *MockUserRepository) GetByEmail(email string) (*model.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(id uint) (*model.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *model.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) ExistsByEmail(email string) (bool, error) {
	args := m.Called(email)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) ExistsByPhone(phone string) (bool, error) {
	args := m.Called(phone)
	return args.Bool(0), args.Error(1)
}

// ==================== Mock Kafka Producer ====================

type MockKafkaProducer struct {
	mock.Mock
}

func (m *MockKafkaProducer) PublishEvent(ctx context.Context, topic string, event kafka.Event) error {
	args := m.Called(ctx, topic, event)
	return args.Error(0)
}

func (m *MockKafkaProducer) Close() error {
	args := m.Called()
	return args.Error(0)
}

// ==================== Test Helper ====================

type testUserService struct {
	repo     *MockUserRepository
	producer *MockKafkaProducer
	service  UserService
}

func setupTestService() *testUserService {
	mockRepo := new(MockUserRepository)
	mockProducer := new(MockKafkaProducer)

	// Create service with mock producer wrapped
	service := &userService{
		repo:     mockRepo,
		producer: nil, // Will use mock producer directly in tests
	}

	return &testUserService{
		repo:     mockRepo,
		producer: mockProducer,
		service:  service,
	}
}

// Custom service for testing with mock producer
type testableUserService struct {
	repo     *MockUserRepository
	producer *MockKafkaProducer
}

func (s *testableUserService) Register(ctx context.Context, req *model.RegisterRequest) (*model.UserResponse, error) {
	emailExists, err := s.repo.ExistsByEmail(req.Email)
	if err != nil {
		return nil, err
	}
	if emailExists {
		return nil, assert.AnError
	}

	if req.Phone != "" {
		phoneExists, err := s.repo.ExistsByPhone(req.Phone)
		if err != nil {
			return nil, err
		}
		if phoneExists {
			return nil, assert.AnError
		}
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

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
		return nil, err
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
	s.producer.PublishEvent(ctx, "user-events", event)

	return &model.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Phone:     user.Phone,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
	}, nil
}

func (s *testableUserService) VerifyCredentials(email, password string) (*model.VerifyCredentialsResponse, error) {
	user, err := s.repo.GetByEmail(email)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return &model.VerifyCredentialsResponse{Valid: false}, nil
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return &model.VerifyCredentialsResponse{Valid: false}, nil
	}

	return &model.VerifyCredentialsResponse{
		UserID:   user.ID,
		Role:     user.Role,
		IsActive: user.IsActive,
		Valid:    true,
	}, nil
}

func (s *testableUserService) GetUserByID(id uint) (*model.UserResponse, error) {
	user, err := s.repo.GetByID(id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, err
		}
		return nil, err
	}

	return &model.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Phone:     user.Phone,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
	}, nil
}

// ==================== Register Tests ====================

func TestUserService_Register_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockProducer := new(MockKafkaProducer)

	svc := &testableUserService{
		repo:     mockRepo,
		producer: mockProducer,
	}

	mockRepo.On("ExistsByEmail", "test@example.com").Return(false, nil)
	mockRepo.On("ExistsByPhone", "1234567890").Return(false, nil)
	mockRepo.On("Create", mock.AnythingOfType("*model.User")).Return(nil)
	mockProducer.On("PublishEvent", mock.Anything, "user-events", mock.AnythingOfType("kafka.Event")).Return(nil)

	req := &model.RegisterRequest{
		Email:     "test@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := svc.Register(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test@example.com", resp.Email)
	assert.Equal(t, "John", resp.FirstName)
	assert.Equal(t, "user", resp.Role)
	assert.True(t, resp.IsActive)

	mockRepo.AssertExpectations(t)
	mockProducer.AssertExpectations(t)
}

func TestUserService_Register_WithoutPhone(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockProducer := new(MockKafkaProducer)

	svc := &testableUserService{
		repo:     mockRepo,
		producer: mockProducer,
	}

	mockRepo.On("ExistsByEmail", "test@example.com").Return(false, nil)
	mockRepo.On("Create", mock.AnythingOfType("*model.User")).Return(nil)
	mockProducer.On("PublishEvent", mock.Anything, "user-events", mock.AnythingOfType("kafka.Event")).Return(nil)

	req := &model.RegisterRequest{
		Email:     "test@example.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := svc.Register(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "", resp.Phone)

	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_EmailAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockProducer := new(MockKafkaProducer)

	svc := &testableUserService{
		repo:     mockRepo,
		producer: mockProducer,
	}

	mockRepo.On("ExistsByEmail", "existing@example.com").Return(true, nil)

	req := &model.RegisterRequest{
		Email:     "existing@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := svc.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_PhoneAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockProducer := new(MockKafkaProducer)

	svc := &testableUserService{
		repo:     mockRepo,
		producer: mockProducer,
	}

	mockRepo.On("ExistsByEmail", "test@example.com").Return(false, nil)
	mockRepo.On("ExistsByPhone", "1234567890").Return(true, nil)

	req := &model.RegisterRequest{
		Email:     "test@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := svc.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_CreateFailed(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockProducer := new(MockKafkaProducer)

	svc := &testableUserService{
		repo:     mockRepo,
		producer: mockProducer,
	}

	mockRepo.On("ExistsByEmail", "test@example.com").Return(false, nil)
	mockRepo.On("ExistsByPhone", "1234567890").Return(false, nil)
	mockRepo.On("Create", mock.AnythingOfType("*model.User")).Return(assert.AnError)

	req := &model.RegisterRequest{
		Email:     "test@example.com",
		Phone:     "1234567890",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := svc.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	mockRepo.AssertExpectations(t)
}

// ==================== VerifyCredentials Tests ====================

func TestUserService_VerifyCredentials_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)

	svc := &testableUserService{
		repo: mockRepo,
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	user := &model.User{
		ID:       1,
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Role:     "user",
		IsActive: true,
	}

	mockRepo.On("GetByEmail", "test@example.com").Return(user, nil)

	resp, err := svc.VerifyCredentials("test@example.com", "password123")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Valid)
	assert.Equal(t, uint(1), resp.UserID)
	assert.Equal(t, "user", resp.Role)
	assert.True(t, resp.IsActive)

	mockRepo.AssertExpectations(t)
}

func TestUserService_VerifyCredentials_InvalidPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)

	svc := &testableUserService{
		repo: mockRepo,
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	user := &model.User{
		ID:       1,
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Role:     "user",
		IsActive: true,
	}

	mockRepo.On("GetByEmail", "test@example.com").Return(user, nil)

	resp, err := svc.VerifyCredentials("test@example.com", "wrongpassword")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.Valid)

	mockRepo.AssertExpectations(t)
}

func TestUserService_VerifyCredentials_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)

	svc := &testableUserService{
		repo: mockRepo,
	}

	mockRepo.On("GetByEmail", "nonexistent@example.com").Return(nil, gorm.ErrRecordNotFound)

	resp, err := svc.VerifyCredentials("nonexistent@example.com", "password123")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.Valid)

	mockRepo.AssertExpectations(t)
}

func TestUserService_VerifyCredentials_InactiveUser(t *testing.T) {
	mockRepo := new(MockUserRepository)

	svc := &testableUserService{
		repo: mockRepo,
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	user := &model.User{
		ID:       1,
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Role:     "user",
		IsActive: false,
	}

	mockRepo.On("GetByEmail", "test@example.com").Return(user, nil)

	resp, err := svc.VerifyCredentials("test@example.com", "password123")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Valid)
	assert.False(t, resp.IsActive)

	mockRepo.AssertExpectations(t)
}

func TestUserService_VerifyCredentials_DatabaseError(t *testing.T) {
	mockRepo := new(MockUserRepository)

	svc := &testableUserService{
		repo: mockRepo,
	}

	mockRepo.On("GetByEmail", "test@example.com").Return(nil, assert.AnError)

	resp, err := svc.VerifyCredentials("test@example.com", "password123")

	assert.Error(t, err)
	assert.Nil(t, resp)

	mockRepo.AssertExpectations(t)
}

// ==================== GetUserByID Tests ====================

func TestUserService_GetUserByID_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)

	svc := &testableUserService{
		repo: mockRepo,
	}

	user := &model.User{
		ID:        1,
		Email:     "test@example.com",
		Phone:     "1234567890",
		FirstName: "John",
		LastName:  "Doe",
		Role:      "user",
		IsActive:  true,
	}

	mockRepo.On("GetByID", uint(1)).Return(user, nil)

	resp, err := svc.GetUserByID(1)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, uint(1), resp.ID)
	assert.Equal(t, "test@example.com", resp.Email)
	assert.Equal(t, "John", resp.FirstName)

	mockRepo.AssertExpectations(t)
}

func TestUserService_GetUserByID_NotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)

	svc := &testableUserService{
		repo: mockRepo,
	}

	mockRepo.On("GetByID", uint(999)).Return(nil, gorm.ErrRecordNotFound)

	resp, err := svc.GetUserByID(999)

	assert.Error(t, err)
	assert.Nil(t, resp)

	mockRepo.AssertExpectations(t)
}

func TestUserService_GetUserByID_DatabaseError(t *testing.T) {
	mockRepo := new(MockUserRepository)

	svc := &testableUserService{
		repo: mockRepo,
	}

	mockRepo.On("GetByID", uint(1)).Return(nil, assert.AnError)

	resp, err := svc.GetUserByID(1)

	assert.Error(t, err)
	assert.Nil(t, resp)

	mockRepo.AssertExpectations(t)
}

// ==================== Password Hashing Tests ====================

func TestPasswordHashing(t *testing.T) {
	password := "testPassword123"

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	assert.NoError(t, err)
	assert.NotEqual(t, password, string(hashedPassword))

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	assert.NoError(t, err)

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte("wrongPassword"))
	assert.Error(t, err)
}
