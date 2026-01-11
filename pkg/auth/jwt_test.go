package auth

import (
	"testing"
	"time"

	"go-event-driven/pkg/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func setupJWTManager() *JWTManager {
	cfg := &config.JWTConfig{
		Secret:                "test-secret-key-for-testing",
		ExpirationHours:       1,
		RefreshExpirationDays: 7,
	}
	return NewJWTManager(cfg)
}

// ==================== NewJWTManager Tests ====================

func TestNewJWTManager(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:                "test-secret",
		ExpirationHours:       24,
		RefreshExpirationDays: 7,
	}

	manager := NewJWTManager(cfg)

	assert.NotNil(t, manager)
	assert.Equal(t, cfg, manager.config)
}

// ==================== GenerateToken Tests ====================

func TestGenerateToken_Success(t *testing.T) {
	manager := setupJWTManager()

	token, err := manager.GenerateToken(1, "test@example.com", "user")

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGenerateToken_DifferentUsers(t *testing.T) {
	manager := setupJWTManager()

	token1, err1 := manager.GenerateToken(1, "user1@example.com", "user")
	token2, err2 := manager.GenerateToken(2, "user2@example.com", "admin")

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NotEqual(t, token1, token2)
}

func TestGenerateToken_ContainsCorrectClaims(t *testing.T) {
	manager := setupJWTManager()

	tokenString, err := manager.GenerateToken(123, "test@example.com", "admin")
	assert.NoError(t, err)

	// Validate and check claims
	claims, err := manager.ValidateToken(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, uint(123), claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, "go-event-driven", claims.Issuer)
	assert.Equal(t, "123", claims.Subject)
}

func TestGenerateToken_HasCorrectExpiration(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:          "test-secret",
		ExpirationHours: 2,
	}
	manager := NewJWTManager(cfg)

	tokenString, err := manager.GenerateToken(1, "test@example.com", "user")
	assert.NoError(t, err)

	claims, err := manager.ValidateToken(tokenString)
	assert.NoError(t, err)

	expectedExpiry := time.Now().Add(2 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, time.Minute)
}

// ==================== GenerateRefreshToken Tests ====================

func TestGenerateRefreshToken_Success(t *testing.T) {
	manager := setupJWTManager()

	token, err := manager.GenerateRefreshToken(1)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGenerateRefreshToken_DifferentFromAccessToken(t *testing.T) {
	manager := setupJWTManager()

	accessToken, _ := manager.GenerateToken(1, "test@example.com", "user")
	refreshToken, _ := manager.GenerateRefreshToken(1)

	assert.NotEqual(t, accessToken, refreshToken)
}

func TestGenerateRefreshToken_HasCorrectIssuer(t *testing.T) {
	manager := setupJWTManager()

	tokenString, err := manager.GenerateRefreshToken(123)
	assert.NoError(t, err)

	// Parse token to check issuer
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret-key-for-testing"), nil
	})
	assert.NoError(t, err)

	claims := token.Claims.(*jwt.RegisteredClaims)
	assert.Equal(t, "go-event-driven-refresh", claims.Issuer)
	assert.Equal(t, "123", claims.Subject)
}

func TestGenerateRefreshToken_HasLongerExpiration(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:                "test-secret",
		ExpirationHours:       1,
		RefreshExpirationDays: 7,
	}
	manager := NewJWTManager(cfg)

	refreshToken, err := manager.GenerateRefreshToken(1)
	assert.NoError(t, err)

	token, _ := jwt.ParseWithClaims(refreshToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil
	})

	claims := token.Claims.(*jwt.RegisteredClaims)
	expectedExpiry := time.Now().Add(7 * 24 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, time.Minute)
}

// ==================== ValidateToken Tests ====================

func TestValidateToken_Success(t *testing.T) {
	manager := setupJWTManager()

	tokenString, _ := manager.GenerateToken(1, "test@example.com", "user")

	claims, err := manager.ValidateToken(tokenString)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, uint(1), claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, "user", claims.Role)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	manager := setupJWTManager()

	claims, err := manager.ValidateToken("invalid-token")

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateToken_MalformedToken(t *testing.T) {
	manager := setupJWTManager()

	claims, err := manager.ValidateToken("not.a.valid.jwt.token")

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateToken_WrongSecret(t *testing.T) {
	manager1 := setupJWTManager()

	cfg2 := &config.JWTConfig{
		Secret:          "different-secret",
		ExpirationHours: 1,
	}
	manager2 := NewJWTManager(cfg2)

	tokenString, _ := manager1.GenerateToken(1, "test@example.com", "user")

	claims, err := manager2.ValidateToken(tokenString)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:          "test-secret",
		ExpirationHours: 0, // Will create token that expires immediately
	}
	manager := NewJWTManager(cfg)

	// Create token with past expiration
	claims := &Claims{
		UserID: 1,
		Email:  "test@example.com",
		Role:   "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Issuer:    "go-event-driven",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret"))

	result, err := manager.ValidateToken(tokenString)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestValidateToken_EmptyToken(t *testing.T) {
	manager := setupJWTManager()

	claims, err := manager.ValidateToken("")

	assert.Error(t, err)
	assert.Nil(t, claims)
}

// ==================== ValidateRefreshToken Tests ====================

func TestValidateRefreshToken_Success(t *testing.T) {
	manager := setupJWTManager()

	tokenString, _ := manager.GenerateRefreshToken(123)

	userID, err := manager.ValidateRefreshToken(tokenString)

	assert.NoError(t, err)
	assert.Equal(t, uint(123), userID)
}

func TestValidateRefreshToken_InvalidToken(t *testing.T) {
	manager := setupJWTManager()

	userID, err := manager.ValidateRefreshToken("invalid-token")

	assert.Error(t, err)
	assert.Equal(t, uint(0), userID)
}

func TestValidateRefreshToken_WrongIssuer(t *testing.T) {
	manager := setupJWTManager()

	// Create token with wrong issuer (using access token issuer)
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "wrong-issuer",
		Subject:   "123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret-key-for-testing"))

	userID, err := manager.ValidateRefreshToken(tokenString)

	assert.Error(t, err)
	assert.Equal(t, uint(0), userID)
	assert.Contains(t, err.Error(), "invalid refresh token issuer")
}

func TestValidateRefreshToken_InvalidUserID(t *testing.T) {
	manager := setupJWTManager()

	// Create token with invalid subject (non-numeric)
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "go-event-driven-refresh",
		Subject:   "not-a-number",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret-key-for-testing"))

	userID, err := manager.ValidateRefreshToken(tokenString)

	assert.Error(t, err)
	assert.Equal(t, uint(0), userID)
	assert.Contains(t, err.Error(), "invalid user ID in token")
}

func TestValidateRefreshToken_ExpiredToken(t *testing.T) {
	manager := setupJWTManager()

	// Create expired refresh token
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		Issuer:    "go-event-driven-refresh",
		Subject:   "123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret-key-for-testing"))

	userID, err := manager.ValidateRefreshToken(tokenString)

	assert.Error(t, err)
	assert.Equal(t, uint(0), userID)
}

func TestValidateRefreshToken_AccessTokenUsedAsRefresh(t *testing.T) {
	manager := setupJWTManager()

	// Generate access token and try to use it as refresh token
	accessToken, _ := manager.GenerateToken(1, "test@example.com", "user")

	userID, err := manager.ValidateRefreshToken(accessToken)

	assert.Error(t, err)
	assert.Equal(t, uint(0), userID)
}

// ==================== Edge Cases ====================

func TestGenerateToken_WithEmptyEmail(t *testing.T) {
	manager := setupJWTManager()

	token, err := manager.GenerateToken(1, "", "user")

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, _ := manager.ValidateToken(token)
	assert.Equal(t, "", claims.Email)
}

func TestGenerateToken_WithEmptyRole(t *testing.T) {
	manager := setupJWTManager()

	token, err := manager.GenerateToken(1, "test@example.com", "")

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, _ := manager.ValidateToken(token)
	assert.Equal(t, "", claims.Role)
}

func TestGenerateToken_WithZeroUserID(t *testing.T) {
	manager := setupJWTManager()

	token, err := manager.GenerateToken(0, "test@example.com", "user")

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, _ := manager.ValidateToken(token)
	assert.Equal(t, uint(0), claims.UserID)
}
