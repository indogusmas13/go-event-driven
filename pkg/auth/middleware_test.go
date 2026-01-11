package auth

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"go-event-driven/pkg/config"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func setupTestApp(jwtManager *JWTManager) *fiber.App {
	app := fiber.New()

	// Protected route with JWT middleware
	app.Get("/protected", JWTMiddleware(jwtManager), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"user_id": c.Locals("user_id"),
			"email":   c.Locals("email"),
			"role":    c.Locals("role"),
		})
	})

	// Admin route with role middleware
	app.Get("/admin", JWTMiddleware(jwtManager), RequireRole("admin"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "admin access granted"})
	})

	// Multi-role route
	app.Get("/staff", JWTMiddleware(jwtManager), RequireRole("admin", "moderator"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "staff access granted"})
	})

	return app
}

func setupMiddlewareJWTManager() *JWTManager {
	cfg := &config.JWTConfig{
		Secret:                "middleware-test-secret",
		ExpirationHours:       1,
		RefreshExpirationDays: 7,
	}
	return NewJWTManager(cfg)
}

// ==================== JWTMiddleware Tests ====================

func TestJWTMiddleware_Success(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(123, "test@example.com", "user")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	assert.Equal(t, float64(123), response["user_id"])
	assert.Equal(t, "test@example.com", response["email"])
	assert.Equal(t, "user", response["role"])
}

func TestJWTMiddleware_MissingAuthorizationHeader(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	req := httptest.NewRequest("GET", "/protected", nil)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, "Authorization header is required", response["error"])
}

func TestJWTMiddleware_EmptyAuthorizationHeader(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestJWTMiddleware_InvalidFormat_NoBearerPrefix(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "test@example.com", "user")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", token) // Missing "Bearer " prefix

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, "Invalid authorization header format", response["error"])
}

func TestJWTMiddleware_InvalidFormat_WrongPrefix(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "test@example.com", "user")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Basic "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestJWTMiddleware_InvalidFormat_TooManyParts(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer token extra")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestJWTMiddleware_InvalidToken(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, "Invalid or expired token", response["error"])
}

func TestJWTMiddleware_ExpiredToken(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:          "test-secret",
		ExpirationHours: -1, // Negative to create expired token
	}
	manager := NewJWTManager(cfg)
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "test@example.com", "user")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestJWTMiddleware_WrongSecret(t *testing.T) {
	manager1 := setupMiddlewareJWTManager()

	cfg2 := &config.JWTConfig{
		Secret:          "different-secret",
		ExpirationHours: 1,
	}
	manager2 := NewJWTManager(cfg2)

	app := setupTestApp(manager1)

	// Generate token with different secret
	token, _ := manager2.GenerateToken(1, "test@example.com", "user")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// ==================== RequireRole Tests ====================

func TestRequireRole_Success_SingleRole(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "admin@example.com", "admin")

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, "admin access granted", response["message"])
}

func TestRequireRole_Success_MultipleRoles_FirstMatch(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "admin@example.com", "admin")

	req := httptest.NewRequest("GET", "/staff", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestRequireRole_Success_MultipleRoles_SecondMatch(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "mod@example.com", "moderator")

	req := httptest.NewRequest("GET", "/staff", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestRequireRole_Forbidden_WrongRole(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "user@example.com", "user")

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, "Insufficient permissions", response["error"])
}

func TestRequireRole_Forbidden_NoMatchInMultipleRoles(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "user@example.com", "user")

	req := httptest.NewRequest("GET", "/staff", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestRequireRole_Forbidden_EmptyRole(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	token, _ := manager.GenerateToken(1, "user@example.com", "")

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestRequireRole_RoleNotInContext(t *testing.T) {
	app := fiber.New()

	// Route with RequireRole but without JWTMiddleware (no role in context)
	app.Get("/no-jwt", RequireRole("admin"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/no-jwt", nil)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, "Role not found in token", response["error"])
}

// ==================== Integration Tests ====================

func TestJWTMiddleware_SetsCorrectLocals(t *testing.T) {
	manager := setupMiddlewareJWTManager()

	app := fiber.New()
	app.Get("/check-locals", JWTMiddleware(manager), func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		email := c.Locals("email")
		role := c.Locals("role")

		return c.JSON(fiber.Map{
			"user_id_type": userID != nil,
			"email_type":   email != nil,
			"role_type":    role != nil,
			"user_id":      userID,
			"email":        email,
			"role":         role,
		})
	})

	token, _ := manager.GenerateToken(42, "local@example.com", "tester")

	req := httptest.NewRequest("GET", "/check-locals", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	assert.True(t, response["user_id_type"].(bool))
	assert.True(t, response["email_type"].(bool))
	assert.True(t, response["role_type"].(bool))
	assert.Equal(t, float64(42), response["user_id"])
	assert.Equal(t, "local@example.com", response["email"])
	assert.Equal(t, "tester", response["role"])
}

func TestMiddlewareChain_JWTThenRole(t *testing.T) {
	manager := setupMiddlewareJWTManager()
	app := setupTestApp(manager)

	// Test that middleware chain works correctly
	testCases := []struct {
		name           string
		role           string
		endpoint       string
		expectedStatus int
	}{
		{"admin accessing admin route", "admin", "/admin", fiber.StatusOK},
		{"user accessing admin route", "user", "/admin", fiber.StatusForbidden},
		{"admin accessing staff route", "admin", "/staff", fiber.StatusOK},
		{"moderator accessing staff route", "moderator", "/staff", fiber.StatusOK},
		{"user accessing staff route", "user", "/staff", fiber.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, _ := manager.GenerateToken(1, "test@example.com", tc.role)

			req := httptest.NewRequest("GET", tc.endpoint, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := app.Test(req)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}
