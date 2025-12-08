package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

func Start() {
	app := fiber.New()

	// Logging chi tiết, dùng logger mặc định
	app.Use(logger.New(logger.Config{
		Format: "${time} | ${ip} | ${method} ${path} | ${status} | ${latency} | ${ua} | ${error}\n",
	}))

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	// Middleware xác thực JWT cho /api/*, bỏ qua nếu là WebSocket upgrade
	app.Use("/api/*", func(c *fiber.Ctx) error {
		if c.Get("Upgrade") == "websocket" {
			return c.Next()
		}
		token := c.Get("Authorization")
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
		if token == "" {
			return c.Status(401).JSON(fiber.Map{"error": "missing_token"})
		}
		parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			// Chỉ chấp nhận HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.ErrUnauthorized
			}
			// TODO: Thay secret key bằng config thực tế
			return []byte("your-secret-key"), nil
		})
		if err != nil || !parsed.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "invalid_token"})
		}
		// Có thể lấy claims ở đây nếu cần
		return c.Next()
	})

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Proxy /api/* to chat-service (placeholder, cần bổ sung proxy thực tế)
	app.All("/api/*", func(c *fiber.Ctx) error {
		// TODO: Thực hiện proxy tới chat-service
		return c.SendStatus(501)
	})

	log.Info().Msg("API Gateway started on :8083")
	app.Listen(":8083")
}
