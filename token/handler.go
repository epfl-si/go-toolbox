package token

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// UnifiedAuthenticator is an interface for authenticating users (returning *token.UnifiedClaims)
// Should be moved to go-toolbox/token
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

		// create HMAC signed token from UnifiedClaims (claims)
		t := NewUnified(*claims)
		encoded, err := t.Sign(secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"access_token": encoded})
	}
}

// PostLoginHandler is the handler that checks the login and password and returns a JWT token
// DEPRECATED: Use UnifiedPostLoginHandler instead
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
