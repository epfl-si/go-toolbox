package authorization

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// GinContextKey is the key used to store values in Gin context
type GinContextKey string

const (
	// GinAuthContextKey is the key for auth context in Gin
	GinAuthContextKey GinContextKey = "auth_context"
	// GinResourceContextKey is the key for resource context in Gin
	GinResourceContextKey GinContextKey = "resource_context"
)

// RequireRole creates a middleware that requires a specific role
func RequireRole(role string, authorizer Authorizer, log *zap.Logger) gin.HandlerFunc {
	if log == nil {
		log = zap.NewNop()
	}

	return func(c *gin.Context) {
		// Extract authentication context
		authCtx, err := GetAuthContext(c)
		if err != nil {
			log.Warn("Authentication context not found",
				zap.Error(err),
				zap.String("path", c.Request.URL.Path),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"details": "No valid authentication context found",
			})
			c.Abort()
			return
		}

		// Check if user has the required role
		if !authorizer.HasRole(authCtx, role) {
			log.Info("Role check failed",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("required_role", role),
				zap.String("path", c.Request.URL.Path),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient permissions",
				"details": fmt.Sprintf("Required role: %s", role),
			})
			c.Abort()
			return
		}

		log.Debug("Role check passed",
			zap.String("identifier", authCtx.GetIdentifier()),
			zap.String("role", role),
			zap.String("path", c.Request.URL.Path),
		)

		c.Next()
	}
}

// RequirePermission creates a middleware that requires a specific permission using a ResourceEnhancer
func RequirePermission(
	permission Permission,
	enhancer ResourceEnhancer,
	authorizer Authorizer,
	log *zap.Logger,
) gin.HandlerFunc {
	if log == nil {
		log = zap.NewNop()
	}

	return func(c *gin.Context) {
		// 1. Extract authentication context from Gin context
		authCtx, err := GetAuthContext(c)
		if err != nil {
			log.Warn("Authentication context not found",
				zap.Error(err),
				zap.String("path", c.Request.URL.Path),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"details": "No valid authentication context found",
			})
			c.Abort()
			return
		}

		// 2. Create initial resource context
		resource := make(ResourceContext)

		// 3. Enhance resource using the new enhancer interface
		if enhancer != nil {
			// Create a context with gin.Context for HTTP extraction
			ctx := WithGinContext(c.Request.Context(), c)
			// Also include auth context for machine-specific enhancements
			ctx = WithAuthContext(ctx, authCtx)

			enhanced, err := enhancer.Enhance(ctx, resource)
			if err != nil {
				log.Error("Failed to enhance resource context",
					zap.Error(err),
					zap.String("identifier", authCtx.GetIdentifier()),
					zap.String("path", c.Request.URL.Path),
					zap.String("enhancer", enhancer.Name()),
				)
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "Invalid request",
					"details": "Failed to extract resource information",
				})
				c.Abort()
				return
			}
			resource = enhanced
		}

		// Store resource context for later use
		c.Set(string(GinResourceContextKey), resource)

		// 4. Check authorization
		authorized, err := authorizer.HasPermission(c.Request.Context(), authCtx, permission, resource)
		if err != nil {
			log.Error("Authorization check failed",
				zap.Error(err),
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("permission", permission.String()),
			)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Authorization check failed",
				"details": "An error occurred while checking permissions",
			})
			c.Abort()
			return
		}

		if !authorized {
			log.Info("Access denied",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("permission", permission.String()),
				zap.String("path", c.Request.URL.Path),
				zap.Bool("is_user", authCtx.IsUser()),
				zap.Bool("is_machine", authCtx.IsMachine()),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient permissions",
				"details": fmt.Sprintf("Required permission: %s", permission.String()),
			})
			c.Abort()
			return
		}

		log.Debug("Access granted",
			zap.String("identifier", authCtx.GetIdentifier()),
			zap.String("permission", permission.String()),
			zap.String("path", c.Request.URL.Path),
		)

		c.Next()
	}
}

// RequireAnyPermission creates a middleware that requires at least one of the specified permissions using ResourceEnhancer
func RequireAnyPermission(
	permissions []Permission,
	enhancer ResourceEnhancer,
	authorizer Authorizer,
	log *zap.Logger,
) gin.HandlerFunc {
	if log == nil {
		log = zap.NewNop()
	}

	return func(c *gin.Context) {
		// Extract authentication context
		authCtx, err := GetAuthContext(c)
		if err != nil {
			log.Warn("Authentication context not found",
				zap.Error(err),
				zap.String("path", c.Request.URL.Path),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"details": "No valid authentication context found",
			})
			c.Abort()
			return
		}

		// Create and enhance resource context
		resource := make(ResourceContext)
		if enhancer != nil {
			ctx := WithGinContext(c.Request.Context(), c)
			ctx = WithAuthContext(ctx, authCtx)

			enhanced, err := enhancer.Enhance(ctx, resource)
			if err != nil {
				log.Error("Failed to enhance resource context",
					zap.Error(err),
					zap.String("identifier", authCtx.GetIdentifier()),
					zap.String("enhancer", enhancer.Name()),
				)
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "Invalid request",
					"details": "Failed to extract resource information",
				})
				c.Abort()
				return
			}
			resource = enhanced
		}

		// Store resource context for later use
		c.Set(string(GinResourceContextKey), resource)

		// Check if user has any of the required permissions
		for _, permission := range permissions {
			authorized, err := authorizer.HasPermission(c.Request.Context(), authCtx, permission, resource)
			if err != nil {
				log.Error("Authorization check failed",
					zap.Error(err),
					zap.String("identifier", authCtx.GetIdentifier()),
					zap.String("permission", permission.String()),
				)
				continue // Try next permission
			}

			if authorized {
				log.Debug("Access granted with permission",
					zap.String("identifier", authCtx.GetIdentifier()),
					zap.String("permission", permission.String()),
					zap.String("path", c.Request.URL.Path),
				)
				c.Next()
				return
			}
		}

		// No permission matched
		log.Info("Access denied - no matching permission",
			zap.String("identifier", authCtx.GetIdentifier()),
			zap.String("path", c.Request.URL.Path),
		)

		permissionStrings := make([]string, len(permissions))
		for i, p := range permissions {
			permissionStrings[i] = p.String()
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error":   "Insufficient permissions",
			"details": fmt.Sprintf("Required one of: %v", permissionStrings),
		})
		c.Abort()
	}
}

// GetAuthContext extracts the auth context from Gin context
func GetAuthContext(c *gin.Context) (AuthContext, error) {
	// Try to get from our key first
	if val, exists := c.Get(string(GinAuthContextKey)); exists {
		if authCtx, ok := val.(AuthContext); ok {
			return authCtx, nil
		}
	}

	// Fallback: try to extract from request context
	if authCtx, ok := GetAuthContextFromCtx(c.Request.Context()); ok {
		return authCtx, nil
	}

	return nil, fmt.Errorf("no authentication context found")
}

// SetAuthContext sets the auth context in Gin context
func SetAuthContext(c *gin.Context, authCtx AuthContext) {
	c.Set(string(GinAuthContextKey), authCtx)
	// Also set in request context for compatibility
	ctx := WithAuthContext(c.Request.Context(), authCtx)
	c.Request = c.Request.WithContext(ctx)
}

// GetResourceContext extracts the resource context from Gin context
func GetResourceContext(c *gin.Context) (ResourceContext, bool) {
	if val, exists := c.Get(string(GinResourceContextKey)); exists {
		if resCtx, ok := val.(ResourceContext); ok {
			return resCtx, true
		}
	}
	return nil, false
}
