// Package token handles JWT tokens manipulation
package token

import (
	"encoding/json"
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
		if claims.Name == "" && claims.Email == "" && claims.PreferredUsername == "" &&
			claims.Gaspar == "" && claims.GivenName == "" && claims.FamilyName == "" {
			return TypeMachine
		}
	}

	// Priority 2: User token indicators
	// User tokens have personal identifiers or service accounts
	if claims.Name != "" || claims.Email != "" || claims.PreferredUsername != "" || claims.Gaspar != "" ||
		claims.UniqueID != "" || claims.GivenName != "" || claims.FamilyName != "" {
		return TypeUser
	}

	return TypeUnknown
}

// IsMachineToken returns true if this is a machine-to-machine token
// Deprecated: Compare GetTokenType(claims) == TypeMachine directly. This function will be removed in v3.0.0.
func IsMachineToken(claims *UnifiedClaims) bool {
	return GetTokenType(claims) == TypeMachine
}

// IsUserToken returns true if this is a user token
// Deprecated: Compare GetTokenType(claims) == TypeUser directly. This function will be removed in v3.0.0.
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
		// Priority 2: Structured name (given + family name)
		if claims.GivenName != "" && claims.FamilyName != "" {
			return fmt.Sprintf("User:%s %s", claims.GivenName, claims.FamilyName)
		}
		// Priority 3: Display name
		if claims.Name != "" {
			return fmt.Sprintf("User:%s", claims.Name)
		}
		// Priority 4: Username
		if claims.PreferredUsername != "" {
			return fmt.Sprintf("User:%s", claims.PreferredUsername)
		}
		// Priority 5: Gaspar username
		if claims.Gaspar != "" {
			return fmt.Sprintf("User:%s", claims.Gaspar)
		}
		// Priority 6: Email
		if claims.Email != "" {
			return fmt.Sprintf("User:%s", claims.Email)
		}
		return "User:Unknown"
	}
	return "Unknown"
}

// GetFullName returns the full name, preferring structured fields when available.
// Returns empty string if no name information is available.
func GetFullName(claims *UnifiedClaims) string {
	// Priority 1: Structured name (most specific)
	if claims.GivenName != "" && claims.FamilyName != "" {
		return fmt.Sprintf("%s %s", claims.GivenName, claims.FamilyName)
	}
	// Priority 2: Display name
	if claims.Name != "" {
		return claims.Name
	}
	// Priority 3: Username as fallback
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}
	// Priority 4: Gaspar username as fallback
	if claims.Gaspar != "" {
		return claims.Gaspar
	}
	return ""
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

// GetAssociatedApplication returns the associated application/client ID from tokens.
// This provides a unified way to get the relevant application ID regardless of token type.
func GetAssociatedApplication(claims *UnifiedClaims) string {
	if claims.AuthorizedParty != "" {
		return claims.AuthorizedParty // v2 tokens
	}
	if claims.AppID != "" {
		return claims.AppID // v1 tokens
	}
	return claims.Audience[0]
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
// Deprecated: Use GetTokenType(claims) == TypeMachine && HasRole(claims, role) instead.
// This function will be removed in v3.0.0.
func HasApplicationRole(claims *UnifiedClaims, role string) bool {
	return GetTokenType(claims) == TypeMachine && HasRole(claims, role)
}

// HasUserRole checks if a user token has a specific role.
// Returns false for machine tokens or if the role is not present.
// This provides symmetry with HasApplicationRole for type-safe role checking.
// Deprecated: Use GetTokenType(claims) == TypeUser && HasRole(claims, role) instead.
// This function will be removed in v3.0.0.
func HasUserRole(claims *UnifiedClaims, role string) bool {
	return GetTokenType(claims) == TypeUser && HasRole(claims, role)
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
	UniqueID   string `json:"uniqueid,omitempty"`    // SCIPER (6 digits) or service account (M + 5 digits)
	Name       string `json:"name,omitempty"`        // Display name (may be full name or empty)
	Email      string `json:"email,omitempty"`       // Primary email address
	Gaspar     string `json:"gaspar,omitempty"`      // Gaspar username
	GivenName  string `json:"given_name,omitempty"`  // Given name (first name) from IdP
	FamilyName string `json:"family_name,omitempty"` // Family name (last name) from IdP
	TenantID   string `json:"tid,omitempty"`         // Azure Entra tenant ID

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

// UnmarshalJSON implements custom unmarshaling with email field fallback
func (c *UnifiedClaims) UnmarshalJSON(data []byte) error {
	// Use type alias to avoid infinite recursion
	type Alias UnifiedClaims
	aux := (*Alias)(c)

	// First, unmarshal normally using default behavior
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// If Email is still empty, check alternative field names
	if c.Email == "" {
		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err == nil {
			for _, key := range []string{"email", "useremail", "mail", "upn"} {
				if v, ok := m[key]; ok {
					if email, ok := v.(string); ok && email != "" {
						c.Email = email
						break
					}
				}
			}
		}
	}

	return nil
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
