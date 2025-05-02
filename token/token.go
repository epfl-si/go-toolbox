// Package token handles JWT tokens manipulation
package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// Authenticater is the interface that wraps the Authenticate method
type Authenticater interface {
	Authenticate(login, pass string) (CustomClaims, error)
}

// CustomClaims is the struct that represents the claims of a JWT token in EPFL context
type CustomClaims struct {
	Sciper string `json:"sciper"`
	jwt.RegisteredClaims
}

// Validate validates the claims of a JWT token
func (m CustomClaims) Validate() error {
	if m.Sciper == "" {
		return errors.New("sciper must be set")
	}
	return nil
}

// Token is the struct that represents a JWT token
type Token struct {
	JWT *jwt.Token
}

// New creates a new JWT token
func New(claims CustomClaims) *Token {
	jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return &Token{JWT: jwt}
}

// Parse parses a JWT token
func Parse(tokenString string, secret []byte) (*Token, error) {
	t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	return &Token{t}, nil
}

// Sign signs a JWT token
func (t *Token) Sign(secret []byte) (string, error) {
	return t.JWT.SignedString([]byte(secret))
}

// Claims returns the claims of a JWT token
func (t *Token) Claims() jwt.MapClaims {
	return t.JWT.Claims.(jwt.MapClaims)
}

// Set sets a claim in a JWT token
func (t *Token) Set(key string, value interface{}) {
	t.Claims()[key] = value
}

// Get gets a claim from a JWT token
func (t *Token) Get(key string) interface{} {
	return t.Claims()[key]
}

// GetString gets a claim from a JWT token as a string
func (t *Token) GetString(key string) string {
	return t.Claims()[key].(string)
}

// ToJSON converts a JWT token to JSON
func (t *Token) ToJSON() (string, error) {
	return t.JWT.Raw, nil
}

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

func GetJwtDataFromHeader(authorizationHeader string) map[string]interface{} {
	rBearerJwt, _ := regexp.Compile(`^Bearer (?:[\w-]*\.){2}[\w-]*$`)
	if rBearerJwt.MatchString(authorizationHeader) {
		authorizationHeader = strings.ReplaceAll(authorizationHeader, "Bearer ", "")

		// get middle part and decode base64
		splits := strings.Split(authorizationHeader, ".")
		if len(splits) != 3 {
			return nil
		}
		// unmarshal jwtData to json
		var data map[string]interface{}
		// decode splits[1] from base64 to json
		dataPart := splits[1]
		// decode base64 part 2 and convert to JSON
		jsonData, err := base64.RawURLEncoding.DecodeString(dataPart)
		if err != nil {
			return nil
		}

		err = json.Unmarshal([]byte(jsonData), &data)
		if err != nil {
			return nil
		}

		return data
	}

	return nil
}

// GinMiddleware is the middleware that checks the JWT token
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
