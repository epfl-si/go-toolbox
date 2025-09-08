// Package token handles JWT tokens manipulation
package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Authenticater is the interface that wraps the Authenticate method
type Authenticater interface {
	Authenticate(login, pass string) (CustomClaims, error)
}

// CustomClaims is the struct that represents the claims of a JWT token in EPFL context
// Deprecated: Use UnifiedClaims for new implementations
type CustomClaims struct {
	Sciper string `json:"sciper"`
	jwt.RegisteredClaims
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
		// Validate the alg is the one expected:
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
