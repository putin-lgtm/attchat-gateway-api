package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

func Start() {
	app := fiber.New()

	// Logging chi tiết
	app.Use(logger.New(logger.Config{
		Format: "${time} | ${ip} | ${method} ${path} | ${status} | ${latency} | ${ua} | ${error}\n",
	}))

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	// Load config
	// Default chat base includes /api/v1 so client can call /api/... on gateway
	chatBase := getenvDefault("CHAT_SERVICE_BASE", "http://localhost:8080/api/v1")
	chatBase = strings.TrimRight(chatBase, "/")
	allowedIssuers := loadAllowedIssuers()
	pubKeyPEM := loadPublicKey()
	if strings.TrimSpace(pubKeyPEM) == "" {
		log.Fatalf("missing JWT public key (set GATEWAY_JWT_PUBLIC_KEY_FILE or GATEWAY_JWT_PUBLIC_KEY)")
	}
	log.Printf("[DEBUG] jwt public key length=%d", len(pubKeyPEM))
	pubKey, err := parseRSAPublicKey(pubKeyPEM)
	if err != nil {
		log.Fatalf("failed to parse JWT public key: %v", err)
	}

	// Auth middleware cho /api/*
	app.Use("/api/*", func(c *fiber.Ctx) error {
		// Bỏ qua các endpoint public
		path := c.Path()
		if path == "/api/auth/login" || path == "/api/auth/refresh" {
			return c.Next()
		}
		// Bỏ qua preflight
		if c.Method() == fiber.MethodOptions {
			return c.Next()
		}
		if strings.EqualFold(c.Get("Upgrade"), "websocket") {
			return c.Next()
		}
		authz := c.Get("Authorization")
		tokenString := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing_token"})
		}
		claims := &jwt.RegisteredClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fiber.ErrUnauthorized
			}
			return pubKey, nil
		})
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_token"})
		}
		// Issuer check
		if len(allowedIssuers) > 0 {
			validIss := false
			for _, iss := range allowedIssuers {
				if claims.Issuer == iss {
					validIss = true
					break
				}
			}
			if !validIss {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_issuer"})
			}
		}
		return c.Next()
	})

	// Root health/info
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":   "healthy",
			"message":  "ATTChat Gateway API is running",
			"version":  "2.0",
			"proxy_to": chatBase,
			"arch":     "gateway-api",
		})
	})

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Proxy /api/* xuống chat-service
	app.All("/api/*", forwardToChat(chatBase))

	port := getenvDefault("GATEWAY_API_PORT", "8083")
	log.Printf("API Gateway started on :%s -> proxy %s", port, chatBase)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

func loadPublicKey() string {
	if path := strings.TrimSpace(os.Getenv("GATEWAY_JWT_PUBLIC_KEY_FILE")); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			log.Printf("[DEBUG] loaded public key from file %s len=%d", path, len(data))
			return string(data)
		}
		log.Printf("WARN: failed to read GATEWAY_JWT_PUBLIC_KEY_FILE=%s", path)
	}
	if v := os.Getenv("GATEWAY_JWT_PUBLIC_KEY"); v != "" {
		log.Printf("[DEBUG] loaded public key from env len=%d", len(v))
		return v
	}
	// fallback local dev
	if data, err := os.ReadFile("./jwt_dev_public.pem"); err == nil {
		log.Printf("[DEBUG] loaded public key from ./jwt_dev_public.pem len=%d", len(data))
		return string(data)
	}
	log.Printf("WARN: no public key found (env/file fallback failed)")
	return ""
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	pemStr = normalizePEM(pemStr)
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	if pkcs1, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pkcs1, nil
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if k, ok := pub.(*rsa.PublicKey); ok {
			return k, nil
		}
		return nil, fmt.Errorf("not RSA public key")
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if k, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return k, nil
		}
		return nil, fmt.Errorf("cert is not RSA")
	}
	return nil, fmt.Errorf("parse public key failed")
}

func normalizePEM(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "\uFEFF")
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		s = strings.Trim(s, "\"")
	}
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func getenvDefault(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func loadAllowedIssuers() []string {
	raw := strings.TrimSpace(os.Getenv("GATEWAY_ALLOWED_ISSUERS"))
	if raw == "" {
		return []string{"attchat"}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func forwardToChat(chatBase string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Build target URL
		targetPath := strings.TrimPrefix(c.OriginalURL(), "/api")
		if !strings.HasPrefix(targetPath, "/") {
			targetPath = "/" + targetPath
		}
		targetURL := chatBase + targetPath

		// Copy incoming request to fasthttp request
		var req fasthttp.Request
		var res fasthttp.Response
		c.Request().CopyTo(&req)
		req.SetRequestURI(targetURL)

		if err := fasthttp.Do(&req, &res); err != nil {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
		}

		// Propagate status, headers, body
		c.Status(res.StatusCode())
		res.Header.VisitAll(func(k, v []byte) {
			c.Response().Header.SetBytesKV(k, v)
		})
		return c.Send(res.Body())
	}
}
