package ratelimit

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

// ==================== Config Tests ====================

func TestAuthLimitConfig(t *testing.T) {
	assert.Equal(t, 5, AuthLimitConfig.Max)
	assert.Equal(t, 1*time.Minute, AuthLimitConfig.Expiration)
}

func TestRefreshLimitConfig(t *testing.T) {
	assert.Equal(t, 10, RefreshLimitConfig.Max)
	assert.Equal(t, 1*time.Minute, RefreshLimitConfig.Expiration)
}

func TestRegisterLimitConfig(t *testing.T) {
	assert.Equal(t, 3, RegisterLimitConfig.Max)
	assert.Equal(t, 1*time.Minute, RegisterLimitConfig.Expiration)
}

func TestAPILimitConfig(t *testing.T) {
	assert.Equal(t, 100, APILimitConfig.Max)
	assert.Equal(t, 1*time.Minute, APILimitConfig.Expiration)
}

// ==================== NewLimiter Tests ====================

func TestNewLimiter_ReturnsHandler(t *testing.T) {
	cfg := Config{
		Max:        5,
		Expiration: 1 * time.Minute,
	}

	handler := NewLimiter(cfg)

	assert.NotNil(t, handler)
}

func TestNewLimiter_AllowsRequestsWithinLimit(t *testing.T) {
	app := fiber.New()

	cfg := Config{
		Max:        3,
		Expiration: 1 * time.Minute,
	}

	app.Get("/test", NewLimiter(cfg), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Make requests within limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")

		resp, err := app.Test(req)

		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}
}

func TestNewLimiter_BlocksExcessRequests(t *testing.T) {
	app := fiber.New()

	cfg := Config{
		Max:        2,
		Expiration: 1 * time.Minute,
	}

	app.Get("/test", NewLimiter(cfg), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Make requests up to limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.101")

		resp, err := app.Test(req)

		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// This request should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.101")

	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Equal(t, "Too many requests", response["error"])
	assert.Equal(t, "Rate limit exceeded. Please try again later.", response["message"])
	assert.Equal(t, "60 seconds", response["retry_after"])
}

func TestNewLimiter_DifferentIPsHaveSeparateLimits(t *testing.T) {
	app := fiber.New()

	cfg := Config{
		Max:        1,
		Expiration: 1 * time.Minute,
	}

	app.Get("/test", NewLimiter(cfg), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// First IP - first request
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.Header.Set("X-Forwarded-For", "192.168.1.1")
	resp1, _ := app.Test(req1)
	assert.Equal(t, fiber.StatusOK, resp1.StatusCode)

	// Second IP - first request (should succeed)
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Forwarded-For", "192.168.1.2")
	resp2, _ := app.Test(req2)
	assert.Equal(t, fiber.StatusOK, resp2.StatusCode)

	// First IP - second request (should be blocked)
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.Header.Set("X-Forwarded-For", "192.168.1.1")
	resp3, _ := app.Test(req3)
	assert.Equal(t, fiber.StatusTooManyRequests, resp3.StatusCode)

	// Second IP - second request (should be blocked)
	req4 := httptest.NewRequest("GET", "/test", nil)
	req4.Header.Set("X-Forwarded-For", "192.168.1.2")
	resp4, _ := app.Test(req4)
	assert.Equal(t, fiber.StatusTooManyRequests, resp4.StatusCode)
}

// ==================== Factory Function Tests ====================

func TestNewAuthLimiter(t *testing.T) {
	handler := NewAuthLimiter()
	assert.NotNil(t, handler)
}

func TestNewRegisterLimiter(t *testing.T) {
	handler := NewRegisterLimiter()
	assert.NotNil(t, handler)
}

func TestNewRefreshLimiter(t *testing.T) {
	handler := NewRefreshLimiter()
	assert.NotNil(t, handler)
}

func TestNewAPILimiter(t *testing.T) {
	handler := NewAPILimiter()
	assert.NotNil(t, handler)
}

// ==================== KeyGenerator Tests ====================

func TestKeyGenerator_UsesXForwardedFor(t *testing.T) {
	app := fiber.New()

	var capturedKey string

	app.Get("/test", func(c *fiber.Ctx) error {
		capturedKey = keyGenerator(c)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	app.Test(req)

	assert.Equal(t, "10.0.0.1", capturedKey)
}

func TestKeyGenerator_FallsBackToIP(t *testing.T) {
	app := fiber.New()

	var capturedKey string

	app.Get("/test", func(c *fiber.Ctx) error {
		capturedKey = keyGenerator(c)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No X-Forwarded-For header

	app.Test(req)

	// Should return the actual IP (0.0.0.0 in test environment)
	assert.NotEmpty(t, capturedKey)
}

// ==================== RateLimitReached Tests ====================

func TestRateLimitReached_ReturnsCorrectResponse(t *testing.T) {
	app := fiber.New()

	cfg := Config{
		Max:        1, // Allow only 1 request
		Expiration: 1 * time.Minute,
	}

	app.Get("/test", NewLimiter(cfg), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	clientIP := "192.168.1.200"

	// First request - should succeed
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.Header.Set("X-Forwarded-For", clientIP)
	resp1, _ := app.Test(req1)
	assert.Equal(t, fiber.StatusOK, resp1.StatusCode)

	// Second request - should be rate limited
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Forwarded-For", clientIP)

	resp, err := app.Test(req2)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	assert.Equal(t, "Too many requests", response["error"])
	assert.Equal(t, "Rate limit exceeded. Please try again later.", response["message"])
	assert.Equal(t, "60 seconds", response["retry_after"])
}

// ==================== Integration Tests ====================

func TestAuthLimiter_Integration(t *testing.T) {
	app := fiber.New()

	app.Post("/login", NewAuthLimiter(), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "logged in"})
	})

	// Should allow 5 requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.50")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 6th request should be blocked
	req := httptest.NewRequest("POST", "/login", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.50")

	resp, _ := app.Test(req)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

func TestRegisterLimiter_Integration(t *testing.T) {
	app := fiber.New()

	app.Post("/register", NewRegisterLimiter(), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "registered"})
	})

	// Should allow 3 requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/register", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.51")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 4th request should be blocked
	req := httptest.NewRequest("POST", "/register", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.51")

	resp, _ := app.Test(req)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

func TestRefreshLimiter_Integration(t *testing.T) {
	app := fiber.New()

	app.Post("/refresh", NewRefreshLimiter(), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "refreshed"})
	})

	// Should allow 10 requests
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/refresh", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.52")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 11th request should be blocked
	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.52")

	resp, _ := app.Test(req)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

func TestAPILimiter_AllowsHigherTraffic(t *testing.T) {
	app := fiber.New()

	app.Get("/api/data", NewAPILimiter(), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"data": "test"})
	})

	// Should allow 100 requests
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/api/data", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.53")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 101st request should be blocked
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.53")

	resp, _ := app.Test(req)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

// ==================== Multiple Endpoints Tests ====================

func TestDifferentEndpointsHaveSeparateLimits(t *testing.T) {
	app := fiber.New()

	app.Post("/login", NewAuthLimiter(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	app.Post("/register", NewRegisterLimiter(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	clientIP := "192.168.1.60"

	// Exhaust login limit (5 requests)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.Header.Set("X-Forwarded-For", clientIP)
		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// Login should now be blocked
	req := httptest.NewRequest("POST", "/login", nil)
	req.Header.Set("X-Forwarded-For", clientIP)
	resp, _ := app.Test(req)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)

	// But register should still work (has its own limiter instance)
	req = httptest.NewRequest("POST", "/register", nil)
	req.Header.Set("X-Forwarded-For", clientIP)
	resp, _ = app.Test(req)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// ==================== Custom Config Tests ====================

func TestCustomConfig(t *testing.T) {
	app := fiber.New()

	customCfg := Config{
		Max:        2,
		Expiration: 30 * time.Second,
	}

	app.Get("/custom", NewLimiter(customCfg), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	clientIP := "192.168.1.70"

	// Should allow 2 requests
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/custom", nil)
		req.Header.Set("X-Forwarded-For", clientIP)
		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 3rd request should be blocked
	req := httptest.NewRequest("GET", "/custom", nil)
	req.Header.Set("X-Forwarded-For", clientIP)
	resp, _ := app.Test(req)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}
