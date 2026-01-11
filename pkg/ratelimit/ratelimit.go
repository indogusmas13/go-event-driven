package ratelimit

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

type Config struct {
	Max        int
	Expiration time.Duration
}

var (
	// AuthLimitConfig - untuk login/register (strict)
	AuthLimitConfig = Config{
		Max:        5,
		Expiration: 1 * time.Minute,
	}

	// RefreshLimitConfig - untuk token refresh
	RefreshLimitConfig = Config{
		Max:        10,
		Expiration: 1 * time.Minute,
	}

	// RegisterLimitConfig - untuk registration (very strict)
	RegisterLimitConfig = Config{
		Max:        3,
		Expiration: 1 * time.Minute,
	}

	// APILimitConfig - untuk general API (relaxed)
	APILimitConfig = Config{
		Max:        100,
		Expiration: 1 * time.Minute,
	}
)

func rateLimitReached(c *fiber.Ctx) error {
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"error":       "Too many requests",
		"message":     "Rate limit exceeded. Please try again later.",
		"retry_after": "60 seconds",
	})
}

func NewLimiter(cfg Config) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               cfg.Max,
		Expiration:        cfg.Expiration,
		KeyGenerator:      keyGenerator,
		LimitReached:      rateLimitReached,
		SkipFailedRequests: false,
		SkipSuccessfulRequests: false,
	})
}

func keyGenerator(c *fiber.Ctx) string {
	// Use X-Forwarded-For if behind proxy, otherwise use IP
	forwarded := c.Get("X-Forwarded-For")
	if forwarded != "" {
		return forwarded
	}
	return c.IP()
}

// NewAuthLimiter - rate limiter untuk auth endpoints (login)
func NewAuthLimiter() fiber.Handler {
	return NewLimiter(AuthLimitConfig)
}

// NewRegisterLimiter - rate limiter untuk registration
func NewRegisterLimiter() fiber.Handler {
	return NewLimiter(RegisterLimitConfig)
}

// NewRefreshLimiter - rate limiter untuk token refresh
func NewRefreshLimiter() fiber.Handler {
	return NewLimiter(RefreshLimitConfig)
}

// NewAPILimiter - rate limiter untuk general API
func NewAPILimiter() fiber.Handler {
	return NewLimiter(APILimitConfig)
}
