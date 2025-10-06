package token

import "github.com/gin-gonic/gin"

// UserContext holds information about the user extracted from a JWT token.
// It provides a simplified, application-friendly view of the user's identity.
type UserContext struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"` // "person", "service", or "unknown"
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	TenantID string   `json:"tenant_id"`
}

// GetUserContext extracts UserContext from gin.Context
// Returns nil if not present or not a user token
func GetUserContext(c *gin.Context) *UserContext {
	if ctx, exists := c.Get(string(ContextKeyUserCtx)); exists {
		if userCtx, ok := ctx.(*UserContext); ok {
			return userCtx
		}
	}
	return nil
}
