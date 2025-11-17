package token

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// contextKey is a custom type for context keys to avoid collisions (Go best practice)
type contextKey string

// Context key constants for type-safe context access
const (
	// Primary context keys
	ContextKeyClaims     contextKey = "claims"
	ContextKeyMachineCtx contextKey = "machine_context"
	ContextKeyUserCtx    contextKey = "user_context"
	ContextKeyIdentity   contextKey = "identity"
)

// extractBearerToken extracts the Bearer token from Authorization header
// Returns the token string (without "Bearer " prefix) or an error
func extractBearerToken(c *gin.Context, headerName string) (string, error) {
	authHeader := c.GetHeader(headerName)
	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	if !strings.HasPrefix(authHeader, "Bearer") {
		return "", fmt.Errorf("token must start with 'Bearer '")
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))

	if token == "Bearer" {
		return "", fmt.Errorf("token is empty")
	}

	return token, nil
}

// MiddlewareConfig defines configuration for the JWT middleware
type MiddlewareConfig struct {
	Validator  TokenValidator // Token validator implementation
	Logger     *zap.Logger    // Logger instance
	ContextKey string         // Key for storing claims in context (default: "claims")
	HeaderName string         // Authorization header name (default: "Authorization")
}

// DefaultMiddlewareConfig returns default middleware configuration
// Deprecated: Construct MiddlewareConfig directly. This function will be removed in v3.0.0.
// Migration: Replace DefaultMiddlewareConfig(validator, logger) with MiddlewareConfig{Validator: validator, Logger: logger}
func DefaultMiddlewareConfig(validator TokenValidator, logger *zap.Logger) MiddlewareConfig {
	return MiddlewareConfig{
		Validator:  validator,
		Logger:     logger,
		ContextKey: string(ContextKeyClaims), // Use type-safe constant
		HeaderName: "Authorization",
	}
}

// UnifiedJWTMiddleware creates middleware that handles JWT token validation
func UnifiedJWTMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.ContextKey == "" {
		config.ContextKey = string(ContextKeyClaims) // Use type-safe constant
	}
	if config.HeaderName == "" {
		config.HeaderName = "Authorization"
	}

	return func(c *gin.Context) {
		// Extract token from Authorization header
		tokenString, err := extractBearerToken(c, config.HeaderName)
		if err != nil {
			config.Logger.Debug("Invalid token format", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(), // Use string representation of error
			})
			c.Abort()
			return
		}

		config.Logger.Debug("Token validation successful",
			zap.String("subject_id", GetSubjectID(claims)),
			zap.Duration("duration", duration))

		// Set unified claims and user info in context
		c.Set(config.ContextKey, claims)

		// Set token-type-specific contexts
		tokenType := GetTokenType(claims) // Single type check
		switch tokenType {
		case TypeMachine:
			machineCtx := &MachineContext{
				ApplicationID:      GetApplicationID(claims),
				ServicePrincipalID: GetServicePrincipalID(claims),
				Roles:              claims.Roles,
				Identity:           GetIdentity(claims),
			}
			c.Set(string(ContextKeyMachineCtx), machineCtx)
			c.Set(string(ContextKeyIdentity), machineCtx.Identity)
		case TypeUser:
			// Create user-specific context using proper UserContext struct
			userCtx := &UserContext{
				ID:       GetSubjectID(claims),
				Type:     "unknown", // EPFL-specific type determination moved to epfl package
				Email:    claims.Email,
				Groups:   claims.Groups,
				TenantID: claims.TenantID,
			}
			c.Set(string(ContextKeyUserCtx), userCtx)
			c.Set(string(ContextKeyIdentity), GetIdentity(claims))
		}

		c.Next()
	}
}

// MachineTokenMiddleware creates a middleware that validates machine tokens
// and requires the token to be a machine token.
func MachineTokenMiddleware(validator TokenValidator, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Create middleware config directly instead of using deprecated DefaultMiddlewareConfig
	middlewareConfig := MiddlewareConfig{
		Validator:  validator,
		Logger:     logger,
		ContextKey: string(ContextKeyClaims),
		HeaderName: "Authorization",
	}

	return func(c *gin.Context) {
		// Extract token from Authorization header
		tokenString, err := extractBearerToken(c, middlewareConfig.HeaderName)
		if err != nil {
			logger.Debug("Invalid token format", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Validate token
		claims, err := middlewareConfig.Validator.ValidateToken(tokenString)
		if err != nil {
			logger.Debug("Token validation failed", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(), // Use string representation of error
			})
			c.Abort()
			return
		}

		// Check if token is a machine token
		tokenType := GetTokenType(claims)
		if tokenType != TypeMachine {
			logger.Debug("Token is not a machine token",
				zap.String("token_type", string(tokenType)))
			c.JSON(http.StatusForbidden, gin.H{
				"error": "machine token required", // Clear, lowercase message
			})
			c.Abort()
			return
		}

		// Set machine context
		machineCtx := ExtractMachineContext(claims)
		c.Set(string(ContextKeyMachineCtx), machineCtx)
		c.Set(string(ContextKeyIdentity), machineCtx.Identity)

		// Set unified claims
		c.Set(middlewareConfig.ContextKey, claims)

		logger.Debug("Machine token validation successful",
			zap.String("app_id", machineCtx.ApplicationID),
			zap.Strings("roles", machineCtx.Roles))

		c.Next()
	}
}
