package websocket

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	router "github.com/luraproject/lura/v2/router/gin"
)

const Namespace = "websocket"

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Configure this based on your security requirements
	},
	HandshakeTimeout: 45 * time.Second,
	ReadBufferSize:   4096,
	WriteBufferSize:  4096,
	// Add subprotocols support for better compatibility
	Subprotocols: []string{"chat", "echo"},
}

// Config represents the WebSocket proxy configuration
type Config struct {
	BackendURL        string        `json:"backend_url"`
	AllowedOrigins    []string      `json:"allowed_origins"`
	ReadBufferSize    int           `json:"read_buffer_size"`
	WriteBufferSize   int           `json:"write_buffer_size"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	PingPeriod        time.Duration `json:"ping_period"`
	Debug             bool          `json:"debug"`
}

// HandlerFactory creates a handler factory that processes WebSocket endpoints
func HandlerFactory(logger logging.Logger, next router.HandlerFactory) router.HandlerFactory {
	return func(cfg *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		// Check if this endpoint has WebSocket configuration
		wsConfig, ok := getWebSocketConfig(cfg)
		if !ok {
			// Not a WebSocket endpoint, pass to next handler
			return next(cfg, p)
		}

		// Configure upgrader based on WebSocket config
		configureUpgrader(wsConfig)

		// Return WebSocket proxy handler
		return NewWebSocketProxyHandler(wsConfig, logger)
	}
}

// NewWebSocketProxyHandler creates a new WebSocket proxy handler for GoFiber backend
func NewWebSocketProxyHandler(cfg Config, logger logging.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.Debug {
			logger.Debug("WebSocket proxy request received")
		}

		// Check if this is actually a WebSocket upgrade request
		if !isWebSocketRequest(c.Request) {
			logger.Warning("Non-WebSocket request to WebSocket endpoint")
			c.JSON(http.StatusBadRequest, gin.H{"error": "WebSocket upgrade required"})
			return
		}

		// Check origin if specified
		if !checkOrigin(c.Request, cfg.AllowedOrigins) {
			logger.Warning("WebSocket connection rejected: invalid origin")
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid origin"})
			return
		}

		// Build backend WebSocket URL first
		backendURL := buildBackendURL(cfg.BackendURL, c.Request.URL, c.Params)
		if cfg.Debug {
			logger.Debug("Backend WebSocket URL:", backendURL)
		}

		// Create headers to forward to GoFiber
		headers := forwardHeaders(c.Request.Header)

		// Add specific headers that GoFiber might expect
		headers.Set("User-Agent", "KrakenD-WebSocket-Proxy/1.0")

		// Try to connect to GoFiber backend first before upgrading client
		backendConn, resp, err := websocket.DefaultDialer.Dial(backendURL, headers)
		if err != nil {
			logger.Error("Failed to connect to GoFiber WebSocket backend:", err.Error())
			if resp != nil {
				logger.Error("Backend response status:", resp.Status)
			}
			c.JSON(http.StatusBadGateway, gin.H{
				"error":   "Failed to connect to backend WebSocket service",
				"details": err.Error(),
			})
			return
		}

		if cfg.Debug {
			logger.Debug("Successfully connected to GoFiber backend")
		}

		// Now upgrade the client connection
		clientConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			logger.Error("WebSocket client upgrade failed:", err.Error())
			backendConn.Close()
			return
		}

		logger.Info("WebSocket proxy connection established between client and GoFiber")

		// Start proxying messages between client and GoFiber backend
		proxyWebSocketConnections(clientConn, backendConn, cfg, logger)
	}
}

// isWebSocketRequest checks if the request is a valid WebSocket upgrade request
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// proxyWebSocketConnections handles bidirectional message proxying
func proxyWebSocketConnections(client, backend *websocket.Conn, cfg Config, logger logging.Logger) {
	done := make(chan struct{}, 2)

	// Set connection deadlines
	if cfg.ConnectionTimeout > 0 {
		client.SetReadDeadline(time.Now().Add(cfg.ConnectionTimeout))
		backend.SetReadDeadline(time.Now().Add(cfg.ConnectionTimeout))
	}

	// Set pong handlers to reset read deadlines
	client.SetPongHandler(func(string) error {
		if cfg.ConnectionTimeout > 0 {
			client.SetReadDeadline(time.Now().Add(cfg.ConnectionTimeout))
		}
		return nil
	})

	backend.SetPongHandler(func(string) error {
		if cfg.ConnectionTimeout > 0 {
			backend.SetReadDeadline(time.Now().Add(cfg.ConnectionTimeout))
		}
		return nil
	})

	// Client to Backend (Forward messages from client to GoFiber)
	go func() {
		defer func() {
			done <- struct{}{}
			if cfg.Debug {
				logger.Debug("Client to backend proxy stopped")
			}
		}()

		for {
			messageType, message, err := client.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					logger.Warning("Client WebSocket unexpected close:", err.Error())
				} else if cfg.Debug {
					logger.Debug("Client connection closed normally")
				}
				return
			}

			if cfg.Debug {
				logger.Debug("Forwarding message from client to GoFiber, type:", messageType, "size:", len(message))
			}

			// Reset read deadline on activity
			if cfg.ConnectionTimeout > 0 {
				client.SetReadDeadline(time.Now().Add(cfg.ConnectionTimeout))
			}

			// Forward message to GoFiber backend
			backend.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err = backend.WriteMessage(messageType, message)
			if err != nil {
				logger.Error("Failed to write to GoFiber backend:", err.Error())
				return
			}
		}
	}()

	// Backend to Client (Forward messages from GoFiber to client)
	go func() {
		defer func() {
			done <- struct{}{}
			if cfg.Debug {
				logger.Debug("Backend to client proxy stopped")
			}
		}()

		for {
			messageType, message, err := backend.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					logger.Warning("GoFiber backend WebSocket unexpected close:", err.Error())
				} else if cfg.Debug {
					logger.Debug("Backend connection closed normally")
				}
				return
			}

			if cfg.Debug {
				logger.Debug("Forwarding message from GoFiber to client, type:", messageType, "size:", len(message))
			}

			// Reset read deadline on activity
			if cfg.ConnectionTimeout > 0 {
				backend.SetReadDeadline(time.Now().Add(cfg.ConnectionTimeout))
			}

			// Forward message to client
			client.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err = client.WriteMessage(messageType, message)
			if err != nil {
				logger.Error("Failed to write to client:", err.Error())
				return
			}
		}
	}()

	// Optional ping/pong handling
	if cfg.PingPeriod > 0 {
		go handlePingPong(client, backend, cfg.PingPeriod, logger, cfg.Debug)
	}

	// Wait for either connection to close
	<-done

	// Close both connections
	client.Close()
	backend.Close()

	logger.Info("WebSocket proxy connection closed")
}

// handlePingPong manages ping/pong messages for connection health
func handlePingPong(client, backend *websocket.Conn, pingPeriod time.Duration, logger logging.Logger, debug bool) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Send ping to client
			client.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := client.WriteMessage(websocket.PingMessage, nil); err != nil {
				if debug {
					logger.Debug("Ping to client failed:", err.Error())
				}
				return
			}

			// Send ping to backend
			backend.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := backend.WriteMessage(websocket.PingMessage, nil); err != nil {
				if debug {
					logger.Debug("Ping to backend failed:", err.Error())
				}
				return
			}

			if debug {
				logger.Debug("Ping messages sent to both client and backend")
			}
		}
	}
}

// getWebSocketConfig extracts WebSocket configuration from endpoint config
func getWebSocketConfig(cfg *config.EndpointConfig) (Config, bool) {
	if cfg.ExtraConfig == nil {
		return Config{}, false
	}

	wsConfigRaw, ok := cfg.ExtraConfig[Namespace]
	if !ok {
		return Config{}, false
	}

	wsConfigMap, ok := wsConfigRaw.(map[string]interface{})
	if !ok {
		return Config{}, false
	}

	wsConfig := Config{
		ReadBufferSize:    4096,
		WriteBufferSize:   4096,
		ConnectionTimeout: 30 * time.Second,
		PingPeriod:        54 * time.Second,
		Debug:             false,
	}

	if backendURL, ok := wsConfigMap["backend_url"].(string); ok {
		wsConfig.BackendURL = backendURL
	}

	if origins, ok := wsConfigMap["allowed_origins"].([]interface{}); ok {
		for _, origin := range origins {
			if originStr, ok := origin.(string); ok {
				wsConfig.AllowedOrigins = append(wsConfig.AllowedOrigins, originStr)
			}
		}
	}

	if readBuffer, ok := wsConfigMap["read_buffer_size"].(float64); ok {
		wsConfig.ReadBufferSize = int(readBuffer)
	}

	if writeBuffer, ok := wsConfigMap["write_buffer_size"].(float64); ok {
		wsConfig.WriteBufferSize = int(writeBuffer)
	}

	if timeout, ok := wsConfigMap["connection_timeout"].(string); ok {
		if duration, err := time.ParseDuration(timeout); err == nil {
			wsConfig.ConnectionTimeout = duration
		}
	}

	if ping, ok := wsConfigMap["ping_period"].(string); ok {
		if duration, err := time.ParseDuration(ping); err == nil {
			wsConfig.PingPeriod = duration
		}
	}

	if debug, ok := wsConfigMap["debug"].(bool); ok {
		wsConfig.Debug = debug
	}

	return wsConfig, true
}

// configureUpgrader sets up the WebSocket upgrader based on config
func configureUpgrader(cfg Config) {
	if cfg.ReadBufferSize > 0 {
		upgrader.ReadBufferSize = cfg.ReadBufferSize
	}
	if cfg.WriteBufferSize > 0 {
		upgrader.WriteBufferSize = cfg.WriteBufferSize
	}
	if cfg.ConnectionTimeout > 0 {
		upgrader.HandshakeTimeout = cfg.ConnectionTimeout
	}
}

// checkOrigin validates the request origin against allowed origins
func checkOrigin(r *http.Request, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		return true
	}

	origin := r.Header.Get("Origin")
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

// buildBackendURL constructs the backend WebSocket URL with path parameters
func buildBackendURL(backendURL string, requestURL *url.URL, params gin.Params) string {
	u, err := url.Parse(backendURL)
	if err != nil {
		return backendURL
	}

	// Change HTTP schemes to WebSocket schemes
	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else if u.Scheme == "https" {
		u.Scheme = "wss"
	}

	// Replace path parameters
	path := u.Path
	for _, param := range params {
		placeholder := "{" + param.Key + "}"
		path = strings.ReplaceAll(path, placeholder, param.Value)
	}
	u.Path = path

	// Add query parameters from the original request
	if requestURL.RawQuery != "" {
		if u.RawQuery != "" {
			u.RawQuery += "&" + requestURL.RawQuery
		} else {
			u.RawQuery = requestURL.RawQuery
		}
	}

	return u.String()
}

// forwardHeaders creates headers to forward to the backend
func forwardHeaders(headers http.Header) http.Header {
	forwardHeaders := make(http.Header)

	// Forward important headers
	headersToForward := []string{
		"Authorization",
		"User-Agent",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Request-ID",
		"Cookie",
		"Origin",
	}

	for _, headerName := range headersToForward {
		if value := headers.Get(headerName); value != "" {
			forwardHeaders.Set(headerName, value)
		}
	}

	return forwardHeaders
}
