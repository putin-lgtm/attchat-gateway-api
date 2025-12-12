package server

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/attchat/attchat-gateway-api/docs"
	docs "github.com/attchat/attchat-gateway-api/docs"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberswagger "github.com/gofiber/swagger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	cpuutil "github.com/shirou/gopsutil/v3/cpu"
	memutil "github.com/shirou/gopsutil/v3/mem"
	netutil "github.com/shirou/gopsutil/v3/net"
	"github.com/valyala/fasthttp"
	"nhooyr.io/websocket"
)

var totalAPICalls int64

type netSample struct {
	bytes uint64
	time  time.Time
}

var (
	netMu         sync.Mutex
	lastNetSample netSample
)

var (
	jsClient     jetstream.JetStream
	jsStreams    []string
	streamsMu    sync.Mutex
	jsReadyError error
	wsBaseURL    string
)

type systemInfo struct {
	CPUPercent string `json:"cpu_used_percent"`
	RAMPercent string `json:"ram_used_percent"`
	RAMUsedMB  string `json:"ram_used_mb"`
	NetMbps    string `json:"net_mbps"`
}

type publishRequest struct {
	Event     string          `json:"event"`             // logical event name, e.g. user_join_chat
	Type      string          `json:"type"`              // stream key, e.g. CHAT/NOTIFY
	RoomID    string          `json:"room_id,omitempty"` // room to broadcast
	UserID    string          `json:"user_id,omitempty"` // optional routing
	BrandID   string          `json:"brand_id,omitempty"`
	ChatID    string          `json:"chat_id,omitempty"`
	Message   string          `json:"message,omitempty"`                      // optional message content
	Payload   json.RawMessage `json:"payload,omitempty" swaggertype:"object"` // full payload if caller already structured
	Timestamp string          `json:"timestamp,omitempty"`                    // ISO string, defaults now
	Subject   string          `json:"subject,omitempty"`                      // optional override
	Stream    string          `json:"stream,omitempty"`                       // optional override stream name
	Token     string          `json:"token,omitempty"`                        // JWT for WS connect
}

type natsEvent struct {
	Type          string          `json:"type"`
	Room          string          `json:"room,omitempty"`
	UserID        string          `json:"user_id,omitempty"`
	BrandID       string          `json:"brand_id,omitempty"`
	ChatID        string          `json:"chat_id,omitempty"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	Timestamp     time.Time       `json:"timestamp"`
	ExcludeConnID string          `json:"exclude_conn_id,omitempty"`
}

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
	wsBaseURL = getenvDefault("GATEWAY_WS_BASE", "ws://localhost:8086/ws")
	docs.SwaggerInfo.Title = "ATTChat Gateway API"
	docs.SwaggerInfo.Version = "2.0"
	docs.SwaggerInfo.BasePath = "/"
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

	// Init NATS / JetStream for publish endpoint
	jsReadyError = initJetStream()
	if jsReadyError != nil {
		log.Printf("WARN: JetStream init failed, /api/publish-chat-event will return 503: %v", jsReadyError)
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

	// Special publish endpoint (không proxy)
	app.Post("/api/publish-chat-event", handlePublishEvent)

	// Root health/info
	app.Get("/", func(c *fiber.Ctx) error {
		sys := systemMetrics()
		return c.JSON(fiber.Map{
			"status":              "healthy",
			"message":             "ATTChat Gateway API is running",
			"version":             "2.0",
			"proxy_to":            chatBase,
			"arch":                "gateway-api",
			"total_api_connected": atomic.LoadInt64(&totalAPICalls),
			"system":              sys,
		})
	})

	// Swagger UI
	app.Get("/swagger/*", fiberswagger.HandlerDefault)

	// Health check
	app.Get("/health", healthHandler)

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
		// Count every proxied API request
		atomic.AddInt64(&totalAPICalls, 1)

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
			log.Printf("[ERROR] proxy %s -> %s failed: %v", c.OriginalURL(), targetURL, err)
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
		}

		if res.StatusCode() >= 400 {
			log.Printf("[WARN] upstream %s responded %d for %s", targetURL, res.StatusCode(), c.OriginalURL())
		}

		// Propagate status, headers, body
		c.Status(res.StatusCode())
		res.Header.VisitAll(func(k, v []byte) {
			c.Response().Header.SetBytesKV(k, v)
		})
		return c.Send(res.Body())
	}
}

// handlePublishEvent publishes chat metadata into JetStream
// @Summary Publish chat event to JetStream
// @Tags chat
// @Accept json
// @Produce json
// @Param payload body publishRequest true "Event payload"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 503 {object} map[string]interface{}
// @Router /api/publish-chat-event [post]
func handlePublishEvent(c *fiber.Ctx) error {
	if jsClient == nil || jsReadyError != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "jetstream_unavailable", "detail": errorString(jsReadyError)})
	}

	var req publishRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body", "detail": err.Error()})
	}

	streamName := strings.TrimSpace(req.Stream)
	if streamName == "" {
		streamName = strings.TrimSpace(req.Type)
	}
	if streamName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing_type", "detail": "type/stream is required to pick JetStream stream"})
	}
	streamName = strings.ToLower(streamName)

	// Pick token for WS connect: prefer body, fallback Authorization header
	token := strings.TrimSpace(req.Token)
	if token == "" {
		authz := c.Get("Authorization")
		token = strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	}
	if token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing_token", "detail": "token is required for WS connect"})
	}

	eventName := strings.TrimSpace(req.Event)
	if eventName == "" {
		eventName = streamName
	}

	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = fmt.Sprintf("%s.events", streamName)
	}

	ts := time.Now().UTC()
	if req.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, req.Timestamp); err == nil {
			ts = parsed
		}
	}

	payload := req.Payload
	if len(payload) == 0 {
		if req.Message != "" {
			payload = json.RawMessage(fmt.Sprintf(`{"message":%q}`, req.Message))
		} else {
			payload = json.RawMessage(`{}`)
		}
	}

	event := natsEvent{
		Type:      eventName,
		Room:      req.RoomID,
		UserID:    req.UserID,
		BrandID:   req.BrandID,
		ChatID:    req.ChatID,
		Payload:   payload,
		Timestamp: ts,
	}

	// Step 1: establish WS to gateway-websocket with given params
	if wsBaseURL == "" {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "ws_base_missing", "detail": "GATEWAY_WS_BASE is not configured"})
	}

	wsURL, err := buildWSURL(wsBaseURL, map[string]string{
		"token":    token,
		"brand_id": req.BrandID,
		"type":     streamName,
		"user_id":  req.UserID,
		"room_id":  req.RoomID,
	})
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_ws_url", "detail": err.Error()})
	}

	wsCtx, wsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer wsCancel()

	conn, resp, err := websocket.Dial(wsCtx, wsURL, nil)
	if err != nil {
		status := fiber.StatusBadGateway
		if resp != nil {
			status = resp.StatusCode
		}
		return c.Status(status).JSON(fiber.Map{"error": "ws_connect_failed", "detail": err.Error(), "status_code": status})
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	if err := ensureStream(streamName); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "stream_init_failed", "detail": err.Error()})
	}

	data, err := json.Marshal(event)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "marshal_failed", "detail": err.Error()})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ack, err := jsClient.Publish(ctx, subject, data)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "publish_failed", "detail": err.Error()})
	}

	return c.JSON(fiber.Map{
		"status":   "ok",
		"stream":   ack.Stream,
		"subject":  subject,
		"seq":      ack.Sequence,
		"ts":       ts,
		"event":    eventName,
		"room_id":  req.RoomID,
		"user_id":  req.UserID,
		"brand_id": req.BrandID,
	})
}

func initJetStream() error {
	natsURL := getenvDefault("GATEWAY_NATS_URL", "nats://localhost:4222")
	streamsRaw := getenvDefault("GATEWAY_NATS_STREAMS", "CHAT")
	jsStreams = parseStreams(streamsRaw)

	nc, err := nats.Connect(natsURL, nats.Name("attchat-gateway-api"))
	if err != nil {
		return err
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return err
	}
	jsClient = js

	for _, stream := range jsStreams {
		if err := ensureStream(stream); err != nil {
			return err
		}
	}
	return nil
}

func ensureStream(streamName string) error {
	if jsClient == nil {
		return fmt.Errorf("jetstream not initialized")
	}

	streamsMu.Lock()
	defer streamsMu.Unlock()

	ctx := context.Background()
	nameCandidates := []string{streamName, strings.ToUpper(streamName), strings.ToLower(streamName)}
	for _, n := range nameCandidates {
		if info, _ := jsClient.Stream(ctx, n); info != nil {
			return nil
		}
	}

	createName := strings.ToUpper(streamName)
	createSubject := strings.ToLower(streamName) + ".>"

	_, err := jsClient.CreateStream(ctx, jetstream.StreamConfig{
		Name:      createName,
		Subjects:  []string{createSubject},
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
	})
	return err
}

func parseStreams(raw string) []string {
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, strings.ToUpper(s))
		}
	}
	return out
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func buildWSURL(base string, params map[string]string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		if strings.TrimSpace(v) != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// healthHandler returns health status
// @Summary Health check
// @Tags health
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /health [get]
func healthHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
		"jetstream": fiber.Map{
			"streams":   jsStreams,
			"connected": jsReadyError == nil,
			"error":     errorString(jsReadyError),
		},
	})
}

// measureNetworkMbps performs a small download against a configurable URL to estimate throughput.
// Default URL downloads 100KB from Cloudflare speed endpoint. Returns -1 on error/timeout.
func measureNetworkMbps() float64 {
	testURL := getenvDefault("GATEWAY_NET_SPEED_URL", "https://speed.cloudflare.com/__down?bytes=100000")
	client := &http.Client{Timeout: 3 * time.Second}

	start := time.Now()
	resp, err := client.Get(testURL)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	n, err := io.Copy(&buf, resp.Body)
	if err != nil {
		return -1
	}
	secs := time.Since(start).Seconds()
	if secs == 0 {
		return -1
	}
	mbps := (float64(n) * 8) / (secs * 1_000_000) // bytes -> bits -> megabits
	return mbps
}

// round2 rounds to 2 decimal places
func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

// networkStatus labels network speed qualitatively
func networkStatus(mbps float64) string {
	if mbps < 0 {
		return "unreachable"
	}
	switch {
	case mbps >= 20:
		return "fast"
	case mbps >= 5:
		return "medium"
	default:
		return "slow"
	}
}

// system metrics (gopsutil)
func systemMetrics() systemInfo {
	cpuP := cpuPercent()
	memP, memUsed := memStats()
	netMbps := netThroughputMbps()
	return systemInfo{
		CPUPercent: fmtPercent(cpuP),
		RAMPercent: fmtPercent(memP),
		RAMUsedMB:  fmtMB(memUsed),
		NetMbps:    fmtMbps(netMbps),
	}
}

func cpuPercent() float64 {
	perc, err := cpuutil.Percent(0, false)
	if err != nil || len(perc) == 0 {
		return -1
	}
	return perc[0]
}

func memStats() (percent float64, usedMB float64) {
	vm, err := memutil.VirtualMemory()
	if err != nil {
		return -1, -1
	}
	return vm.UsedPercent, float64(vm.Used) / (1024 * 1024)
}

func netThroughputMbps() float64 {
	counters, err := netutil.IOCounters(true)
	if err != nil || len(counters) == 0 {
		return -1
	}
	var total uint64
	for _, c := range counters {
		total += c.BytesRecv + c.BytesSent
	}
	now := time.Now()

	netMu.Lock()
	defer netMu.Unlock()

	if lastNetSample.time.IsZero() {
		lastNetSample = netSample{bytes: total, time: now}
		return 0
	}
	deltaBytes := total - lastNetSample.bytes
	elapsed := now.Sub(lastNetSample.time).Seconds()
	lastNetSample = netSample{bytes: total, time: now}
	if elapsed <= 0 {
		return 0
	}
	return (float64(deltaBytes) * 8) / (elapsed * 1_000_000)
}

// format helpers
func fmtPercent(v float64) string {
	if v < 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.2f%%", v)
}

func fmtMB(v float64) string {
	if v < 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.2f MB", v)
}

func fmtMbps(v float64) string {
	if v < 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.2f Mbps", v)
}
