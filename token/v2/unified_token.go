// Package token handles JWT tokens manipulation
package token

import (
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Type represents the type of token
type Type string

const (
	// TypeUser indicate a user token
	TypeUser Type = "user"
	// TypeMachine indicate a machine-to-machine (application) token
	TypeMachine Type = "machine"
	// TypeUnknown indicate an unknown token type
	TypeUnknown Type = "unknown"
)

// GetTokenType determines if this is a user or machine token
func GetTokenType(claims *UnifiedClaims) Type {
	// Priority 1: Explicit machine token indicators
	// Machine tokens have azp/appid + roles, and lack user-specific fields
	if (claims.AuthorizedParty != "" || claims.AppID != "") && len(claims.Roles) > 0 {
		// Verify absence of user fields for confirmation
		if claims.Name == "" && claims.Email == "" && claims.PreferredUsername == "" {
			return TypeMachine
		}
	}

	// Priority 2: User token indicators
	// User tokens have personal identifiers or service accounts
	if claims.Name != "" || claims.Email != "" || claims.PreferredUsername != "" || claims.UniqueID != "" {
		return TypeUser
	}

	return TypeUnknown
}

// IsMachineToken returns true if this is a machine-to-machine token
func IsMachineToken(claims *UnifiedClaims) bool {
	return GetTokenType(claims) == TypeMachine
}

// IsUserToken returns true if this is a user token
func IsUserToken(claims *UnifiedClaims) bool {
	return GetTokenType(claims) == TypeUser
}

// GetIdentity returns a unified identity string for logging/audit
func GetIdentity(claims *UnifiedClaims) string {
	switch GetTokenType(claims) {
	case TypeMachine:
		// Priority 1: Application identity (most specific)
		appID := GetApplicationID(claims)
		if appID != "" {
			return fmt.Sprintf("Application:%s", appID)
		}
		// Priority 2: Service Principal by ObjectID
		if claims.ObjectID != "" {
			return fmt.Sprintf("ServicePrincipal:%s", claims.ObjectID)
		}
		// Fallback
		return "Machine:Unknown"
	case TypeUser:
		// Priority 1: UniqueID (SCIPER or service account)
		if claims.UniqueID != "" {
			return fmt.Sprintf("User:%s", claims.UniqueID)
		}
		// Priority 3: Username
		if claims.PreferredUsername != "" {
			return fmt.Sprintf("User:%s", claims.PreferredUsername)
		}
		// Priority 4: Email
		if claims.Email != "" {
			return fmt.Sprintf("User:%s", claims.Email)
		}
		return "User:Unknown"
	}
	return "Unknown"
}

// GetApplicationID returns the application/client ID from machine tokens.
// For v2 tokens, returns AuthorizedParty (azp). For v1 tokens, falls back to AppID.
// Returns empty string for user tokens or if no application ID is present.
func GetApplicationID(claims *UnifiedClaims) string {
	if claims.AuthorizedParty != "" {
		return claims.AuthorizedParty // v2 tokens
	}
	return claims.AppID // v1 tokens fallback
}

// GetServicePrincipalID returns the service principal object ID for machine tokens.
// Returns ObjectID (oid) if present, otherwise falls back to ApplicationID.
// The ObjectID represents the service principal instance in the directory.
func GetServicePrincipalID(claims *UnifiedClaims) string {
	if claims.ObjectID != "" {
		return claims.ObjectID
	}
	return GetApplicationID(claims) // fallback
}

// HasRole checks if the token has a specific role.
// Returns true if the role is present in claims.Roles, regardless of token type.
func HasRole(claims *UnifiedClaims, role string) bool {
	for _, r := range claims.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasApplicationRole checks if a machine token has a specific application role.
// Returns false for user tokens or if the role is not present.
// This is safer than using HasRole() directly as it validates token type first.
func HasApplicationRole(claims *UnifiedClaims, role string) bool {
	return IsMachineToken(claims) && HasRole(claims, role)
}

// HasUserRole checks if a user token has a specific role.
// Returns false for machine tokens or if the role is not present.
// This provides symmetry with HasApplicationRole for type-safe role checking.
func HasUserRole(claims *UnifiedClaims, role string) bool {
	return IsUserToken(claims) && HasRole(claims, role)
}

// Unit represents an EPFL organizational unit with its hierarchy information
type Unit struct {
	ID       string   `json:"id"`       // Unit ID (numeric string)
	Name     string   `json:"name"`     // Display name
	CF       string   `json:"cf"`       // Cost center identifier
	Path     string   `json:"path"`     // Hierarchical path
	Children []string `json:"children"` // List of child unit IDs
}

// UnifiedClaims supports both local and Entra different token types
// User tokens and application tokens (machine-to-machine)
type UnifiedClaims struct {
	jwt.RegisteredClaims // Standard JWT claims (iss, sub, exp, etc.)

	// Core identifiers
	UniqueID string `json:"uniqueid,omitempty"` // SCIPER (6 digits) or service account (M + 5 digits)
	Name     string `json:"name,omitempty"`     // Display name
	Email    string `json:"email,omitempty"`    // Primary email address
	TenantID string `json:"tid,omitempty"`      // Azure Entra tenant ID

	// Machine-to-machine specific claims
	AuthorizedParty string `json:"azp,omitempty"`   // AppId of the client application (v2 tokens)
	AppID           string `json:"appid,omitempty"` // For backward compatibility (v1 tokens)
	ObjectID        string `json:"oid,omitempty"`   // Service Principal Object ID

	// User specific claims
	PreferredUsername string `json:"preferred_username,omitempty"`

	// Authorization
	Groups []string `json:"groups,omitempty"` // Group memberships
	Scopes []string `json:"scopes,omitempty"` // Token scopes
	Units  []Unit   `json:"units,omitempty"`  // EPFL unit info with hierarchy
	Roles  []string `json:"roles,omitempty"`  // User roles or App Roles (e.g., ["default_access"])

}

// SignUnified creates and signs a JWT token with UnifiedClaims using HMAC
// Returns the signed token string directly for clean API design
func SignUnified(claims UnifiedClaims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// ParseUnifiedHMAC parses a JWT token into UnifiedClaims using HMAC validation
func ParseUnifiedHMAC(tokenString string, secret []byte) (*UnifiedClaims, error) {
	claims := &UnifiedClaims{}
	t, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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

// NewMachineTokenForTesting creates a machine token for testing
func NewMachineTokenForTesting(appID string, roles []string, secret []byte) (string, error) {
	claims := UnifiedClaims{
		AuthorizedParty: appID,
		ObjectID:        fmt.Sprintf("sp-%s", appID), // Simulated service principal ID
		Roles:           roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("app:%s", appID),
			Issuer:    "https://test-issuer.local",
			Audience:  []string{"test-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	return SignUnified(claims, secret)
}
