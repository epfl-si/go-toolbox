// Package token handles JWT tokens manipulation
package token

import (
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Unit represents an EPFL organizational unit with its hierarchy information
type Unit struct {
	ID       string   `json:"id"`       // Unit ID (numeric string)
	Name     string   `json:"name"`     // Display name
	CF       string   `json:"cf"`       // Cost center identifier
	Path     string   `json:"path"`     // Hierarchical path
	Children []string `json:"children"` // List of child unit IDs
}

// UnifiedClaims supports both local HMAC and Entra JWKS token formats
type UnifiedClaims struct {
	// Core identifiers
	UniqueID string `json:"uniqueid,omitempty"` // SCIPER (6 digits) or service account (M + 5 digits)
	Name     string `json:"name,omitempty"`     // Display name
	Email    string `json:"email,omitempty"`    // Primary email address
	TenantID string `json:"tid,omitempty"`      // Azure Entra tenant ID

	// Authorization
	Groups []string `json:"groups,omitempty"` // Group memberships
	Scopes []string `json:"scopes,omitempty"` // Token scopes
	Units  []Unit   `json:"units,omitempty"`  // EPFL unit info with hierarchy
	Roles  []string `json:"roles,omitempty"`  // User roles

	jwt.RegisteredClaims // Standard JWT claims (iss, sub, exp, etc.)
}

// ToUnifiedClaims converts CustomClaims to UnifiedClaims for backward compatibility
func (c CustomClaims) ToUnifiedClaims() UnifiedClaims {
	return UnifiedClaims{
		UniqueID:         c.Sciper, // Map sciper to uniqueid
		RegisteredClaims: c.RegisteredClaims,
	}
}

// ToCustomClaims converts UnifiedClaims to CustomClaims for backward compatibility
func (u UnifiedClaims) ToCustomClaims() CustomClaims {
	return CustomClaims{
		Sciper:           u.UniqueID, // Map uniqueid back to sciper
		RegisteredClaims: u.RegisteredClaims,
	}
}

// ParseUnified parses a JWT token into UnifiedClaims
func ParseUnified(tokenString string, secret []byte) (*UnifiedClaims, error) {
	claims := &UnifiedClaims{}
	t, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if !t.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return claims, nil
}

// NewUnified creates a new JWT token with UnifiedClaims
func NewUnified(claims UnifiedClaims) *Token {
	jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return &Token{JWT: jwt}
}
