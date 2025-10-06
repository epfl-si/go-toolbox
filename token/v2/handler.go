package token

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// UnifiedAuthenticater is an interface for authenticating users (returning *UnifiedClaims)
type UnifiedAuthenticater interface {
	Authenticate(login, pass string) (*UnifiedClaims, error)
}

// UnifiedPostLoginHandler creates a Gin handler for user login.
// It authenticates credentials using the provided UnifiedAuthenticater, and if successful,
// issues a new HMAC-signed JWT containing the UnifiedClaims.
func UnifiedPostLoginHandler(log *zap.Logger, auth UnifiedAuthenticater, secret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		login := c.PostForm("login")
		pass := c.PostForm("pass")

		claims, err := auth.Authenticate(login, pass)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		// Create HMAC signed token from UnifiedClaims using clean API
		encoded, err := SignUnified(*claims, secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"access_token": encoded})
	}
}
