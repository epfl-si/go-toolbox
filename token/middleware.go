package token

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// PostLoginHandler is the handler that checks the login and password and returns a JWT token
func PostLoginHandler(log *zap.Logger, auth Authenticater, secret []byte) gin.HandlerFunc {
	log.Info("Creating login handler")
	return func(c *gin.Context) {
		login := c.PostForm("login")
		pass := c.PostForm("pass")

		log.Info("Login attempt", zap.String("login", login))

		claims, err := auth.Authenticate(login, pass)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		t := New(claims)
		encoded, err := t.Sign(secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"access_token": encoded})
	}
}

// MiddlewareConfig defines configuration for the JWT middleware
type MiddlewareConfig struct {
	Validator  TokenValidator // Token validator implementation
	Logger     *zap.Logger    // Logger instance
	ContextKey string         // Key for storing claims in context (default: "claims")
	HeaderName string         // Authorization header name (default: "Authorization")
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig(validator TokenValidator, logger *zap.Logger) MiddlewareConfig {
	return MiddlewareConfig{
		Validator:  validator,
		Logger:     logger,
		ContextKey: "claims",
		HeaderName: "Authorization",
	}
}

// UnifiedJWTMiddleware creates middleware that handles JWT token validation
func UnifiedJWTMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.ContextKey == "" {
		config.ContextKey = "claims"
	}
	if config.HeaderName == "" {
		config.HeaderName = "Authorization"
	}

	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader(config.HeaderName)
		if authHeader == "" {
			config.Logger.Debug("Missing authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authorization header missing",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			config.Logger.Debug("Invalid token format", zap.String("header", authHeader))
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": fmt.Sprintf("token must start with %s", "Bearer "),
			})
			c.Abort()
			return
		}

		// Validate token
		start := time.Now()
		claims, err := config.Validator.ValidateToken(tokenString)
		duration := time.Since(start)

		if err != nil {
			config.Logger.Debug("Token validation failed",
				zap.Error(err),
				zap.Duration("duration", duration))
			c.JSON(http.StatusUnauthorized, gin.H{"error": err})
			c.Abort()
			return
		}

		config.Logger.Debug("Token validation successful",
			zap.String("user_id", GetUserID(claims)),
			zap.String("user_type", GetUserType(claims)),
			zap.Duration("duration", duration))

		// Set unified claims and user info in context
		c.Set(config.ContextKey, claims)
		c.Set("user_id", GetUserID(claims))
		c.Set("user_type", GetUserType(claims))
		c.Set("user_email", claims.Email)

		c.Next()
	}
}

// GinMiddleware is the middleware that checks the JWT token
// Deprecated: Use UnifiedJWTMiddleware instead for better flexibility and unified token support
func GinMiddleware(secret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorizationHeaderString := c.GetHeader("Authorization")
		if authorizationHeaderString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		// Check that the authorization header starts with "Bearer"
		if len(authorizationHeaderString) < 7 || authorizationHeaderString[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract the token from the authorization header
		tokenString := authorizationHeaderString[7:]

		t, err := Parse(tokenString, secret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("token", t)
		c.Next()
	}
}