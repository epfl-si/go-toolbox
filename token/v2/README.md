# Token v2 - Clean JWT Token Validation Library

The `token` package (v2) provides a modern, clean JWT token validation library with support for both HMAC and JWKS (RS256/ES256) token validation. 
This v2 is a clean refactor trying to break free from backward compatibility constraints/cruft.

## Features

- **Dual Validation**: HMAC (HS256) and JWKS (RS256/ES256) support  
- **Auto-Detection**: Automatically chooses validation method based on token algorithm
- **Security Hardened**: Built-in `alg=none` protection, configurable issuer/audience validation
- **Production Ready**: HTTP timeouts, goroutine lifecycle management, proper resource cleanup
- **Machine Token Support**: Full support for Microsoft Entra ID application tokens
- **Gin Middleware**: Ready-to-use middleware for web applications
- **Type Safety**: Strong typing with proper context extraction helpers
- **Better Error Handling**: With sentinel errors

## Quick Start

### Basic HMAC Token Usage

```go
package main

import (
    "fmt"
    "time"
    jwt "github.com/golang-jwt/jwt/v5"
    "github.com/epfl-si/go-toolbox/token/v2"
)

func main() {
    // Create token claims
    claims := token.UnifiedClaims{
        UniqueID: "123456", // SCIPER or service account ID
        Name:     "John Doe",
        Email:    "john.doe@epfl.ch",
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   "john.doe@epfl.ch",
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    secret := []byte("your-secret-key")

    // Sign token using clean API
    tokenString, err := token.SignUnified(claims, secret)
    if err != nil {
        panic(err)
    }

    // Parse token using clean API
    parsedClaims, err := token.ParseUnifiedHMAC(tokenString, secret)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Principal ID: %s\n", token.GetPrincipalID(parsedClaims))
    fmt.Printf("Is Person: %t\n", token.IsPerson(parsedClaims))
}
```

### Generic Validator (Auto-Detection)

```go
package main

import (
    "time"
    "go.uber.org/zap"
    "github.com/epfl-si/go-toolbox/token/v2"
)

func main() {
    logger := zap.NewNop()

    // Configure validator for both HMAC and JWKS
    config := token.Config{
        Method: token.SigningPublicKey, // Primary method
        Secret: []byte("hmac-fallback-secret"), // Fallback for HMAC tokens
        JWKSConfig: &token.JWKSConfig{
            BaseURL:     "https://login.microsoftonline.com",
            KeyCacheTTL: 5 * time.Minute,
        },
        // Optional: Add validation constraints
        RequiredIssuer: "https://sts.windows.net/your-tenant-id/",
        RequiredAudience: []string{"api://your-app-id"},
    }

    validator, err := token.NewGenericValidator(config, logger)
    if err != nil {
        panic(err)
    }
    defer validator.Close() // Important: cleanup resources

    // Validate any token - auto-detects HMAC vs JWKS
    claims, err := validator.ValidateToken(tokenString)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Token validated: %s\n", token.GetIdentity(claims))
}
```

### Gin Middleware Integration

```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
    "github.com/epfl-si/go-toolbox/token/v2"
)

func main() {
    logger := zap.NewNop()
    
    // Option 1: Pre-configured Entra middleware
    middleware, err := token.NewEntraMiddleware([]byte("hmac-secret"), logger)
    if err != nil {
        panic(err)
    }

    // Option 2: Custom validator configuration
    config := token.Config{
        Method: token.SigningPublicKey,
        Secret: []byte("hmac-secret"),
        JWKSConfig: &token.JWKSConfig{
            BaseURL:     "https://login.microsoftonline.com",
            KeyCacheTTL: 5 * time.Minute,
        },
    }
    validator, _ := token.NewGenericValidator(config, logger)
    middlewareConfig := token.DefaultMiddlewareConfig(validator, logger)
    customMiddleware := token.UnifiedJWTMiddleware(middlewareConfig)

    router := gin.New()
    
    // Apply middleware to all routes
    router.Use(customMiddleware)
    
    router.GET("/api/user-data", func(c *gin.Context) {
        // Extract validated claims
        claims, _ := c.Get("claims")
        userClaims := claims.(*token.UnifiedClaims)
        
        // Type-safe context extraction
        if token.IsUserToken(userClaims) {
            userCtx := token.GetUserContext(c) // Helper function
            // Handle user token
        } else if token.IsMachineToken(userClaims) {
            machineCtx := token.GetMachineContext(c) // Helper function  
            // Handle machine token
        }
    })
}
```

### Token Extraction

The package provides a utility function to extract JWT tokens from HTTP headers:

```go
// Extract token from Authorization header
tokenString, err := token.ExtractBearerTokenFromGinContext(c, "Authorization")
if err != nil {
    // Handle missing or malformed token
    return
}

// Use the token string directly or validate it
claims, err := validator.ValidateToken(tokenString)
```

This function:
- Extracts the token from the specified header (default: "Authorization")
- Verifies it has the "Bearer" prefix
- Returns the token string with the "Bearer" prefix removed
- Returns appropriate errors for missing or malformed tokens

### Machine-to-Machine Tokens

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/epfl-si/go-toolbox/token/v2"
)

func main() {
    logger := zap.NewNop()
    validator := token.NewHMACValidator([]byte("secret"), logger, token.Config{})

    router := gin.New()
    
    // Machine-only endpoint
    router.Use(token.MachineTokenMiddleware(validator, logger))
    router.POST("/api/admin-action", func(c *gin.Context) {
        // Only machine tokens reach here
        machineCtx, _ := c.Get("machine_context")
        ctx := machineCtx.(*token.MachineContext)
        
        // Example: Check for a specific role
        // if ctx.HasRole("admin.write") { ... }
    })
}
```

## Advanced Usage Patterns

### Validator Composition with ChainedValidator

ChainedValidator enables **composable validation** by trying validators sequentially until one succeeds. This allows you to:

1. **Add validation layers** beyond cryptographic verification
2. **Handle secret rotation** gracefully
3. **Support multi-tenant scenarios** with different validation rules
4. **Mock custom token validation** for testing for example (where you could associate a specific "token string to a UnifiedClaims)

#### Example: Add Time Window Validation

```go
// Custom validator that checks token age
type MaxAgeValidator struct {
    inner  token.TokenValidator
    maxAge time.Duration
}

func (v *MaxAgeValidator) ValidateToken(tokenString string) (*token.UnifiedClaims, error) {
    claims, err := v.inner.ValidateToken(tokenString)
    if err != nil {
        return nil, err
    }

    if time.Since(claims.IssuedAt.Time) > v.maxAge {
        return nil, fmt.Errorf("token exceeds maximum age of %v", v.maxAge)
    }

    return claims, nil
}

// Usage with middleware
baseValidator, _ := token.NewGenericValidator(config, logger)
strictValidator := &MaxAgeValidator{
    inner:  baseValidator,
    maxAge: 5 * time.Minute,
}

router.Use(token.UnifiedJWTMiddleware(
    token.DefaultMiddlewareConfig(strictValidator, logger),
))
```

#### Example: Secret Rotation

```go
// Accept tokens signed with either old or new secret
rotatingValidator := token.NewChainedValidator([]token.TokenValidator{
    token.NewHMACValidator(newSecret, logger, config), // Try new secret first
    token.NewHMACValidator(oldSecret, logger, config), // Fallback to old
}, logger)

// Use in middleware
middlewareConfig := token.DefaultMiddlewareConfig(rotatingValidator, logger)
router.Use(token.UnifiedJWTMiddleware(middlewareConfig))
```

#### Example: Multi-Tenant Validation

```go
// Different JWKS endpoints or validation rules per tenant
chainedValidator := token.NewChainedValidator([]token.TokenValidator{
    newTenantAValidator(configA), // Try tenant A validation first
    newTenantBValidator(configB), // Fallback to tenant B
}, logger)
```

#### Example: Custom Business Rule Validation

```go
// Rate limiting validator
type RateLimitValidator struct {
    inner     token.TokenValidator
    limiter   map[string]time.Time
    mutex     sync.RWMutex
    rateLimit time.Duration
}

func (v *RateLimitValidator) ValidateToken(tokenString string) (*token.UnifiedClaims, error) {
    claims, err := v.inner.ValidateToken(tokenString)
    if err != nil {
        return nil, err
    }

    userID := token.GetPrincipalID(claims)
    v.mutex.RLock()
    lastSeen, exists := v.limiter[userID]
    v.mutex.RUnlock()

    if exists && time.Since(lastSeen) < v.rateLimit {
        return nil, fmt.Errorf("rate limit exceeded for user %s", userID)
    }

    v.mutex.Lock()
    v.limiter[userID] = time.Now()
    v.mutex.Unlock()

    return claims, nil
}

// Chain: Crypto validation → Rate limiting → Business rules
chain := token.NewChainedValidator([]token.TokenValidator{
    token.NewGenericValidator(config, logger),
    &RateLimitValidator{rateLimit: time.Minute},
    &CustomBusinessRuleValidator{...},
}, logger)
```

**When to Use ChainedValidator:**
- Adding custom validation logic (rate limiting, time windows, business rules)
- Secret rotation periods
- Multi-tenant with different validation requirements
- Graceful fallback between validation methods
When to **NOT** use ChainedValidator:
- Simple HMAC + JWKS auto-detection (use GenericValidator instead)

## API Reference

### Core Types

#### UnifiedClaims

The main claims structure supporting both user and machine tokens:

```go
type UnifiedClaims struct {
    jwt.RegisteredClaims // Standard JWT claims (iss, sub, exp, etc.)

    // Core identifiers
    UniqueID string `json:"uniqueid,omitempty"` // SCIPER (6 digits) or service account (M + 5 digits)
    Name     string `json:"name,omitempty"`     // Display name
    Email    string `json:"email,omitempty"`    // Primary email address
    TenantID string `json:"tid,omitempty"`      // Azure Entra tenant ID

    // Machine token specific
    AuthorizedParty string `json:"azp,omitempty"`   // Application ID (v2 tokens)
    AppID           string `json:"appid,omitempty"` // Application ID (v1 tokens)
    ObjectID        string `json:"oid,omitempty"`   // Service Principal Object ID

    // User token specific  
    PreferredUsername string `json:"preferred_username,omitempty"`

    // Authorization
    Groups []string `json:"groups,omitempty"` // Group memberships
    Scopes []string `json:"scopes,omitempty"` // Token scopes
    Units  []Unit   `json:"units,omitempty"`  // EPFL unit info with hierarchy
    Roles  []string `json:"roles,omitempty"`  // User roles or App Roles
}
```

### Clean Token API

```go
// Create and sign HMAC token
func SignUnified(claims UnifiedClaims, secret []byte) (string, error)

// Parse HMAC token  
func ParseUnifiedHMAC(tokenString string, secret []byte) (*UnifiedClaims, error)

// Testing helper
func NewMachineTokenForTesting(appID string, roles []string, secret []byte) (string, error)
```

### Validation API

```go
// Validation public interface
type TokenValidator interface {
    ValidateToken(tokenString string) (*UnifiedClaims, error)
}

// Generic validator with auto-detection
func NewGenericValidator(config Config, logger *zap.Logger) (*GenericValidator, error)

// Specific validators
func NewHMACValidator(secret []byte, logger *zap.Logger, config Config) *HMACValidator
func NewJWKSValidator(baseURL, tenantID string, cacheTTL time.Duration, logger *zap.Logger) *JWKSValidator
func NewJWKSValidatorWithClient(baseURL, tenantID string, cacheTTL time.Duration, logger *zap.Logger, client *http.Client, config Config) *JWKSValidator
```

### Token Classification

```go
// Token type detection
func GetTokenType(claims *UnifiedClaims) Type // Returns TypeUser, TypeMachine, or TypeUnknown
func IsMachineToken(claims *UnifiedClaims) bool
func IsUserToken(claims *UnifiedClaims) bool

// User classification  
func IsPerson(claims *UnifiedClaims) bool     // 6-digit SCIPER
func IsService(claims *UnifiedClaims) bool    // M+5digits service account
func GetUserType(claims *UnifiedClaims) string // "person", "service", "unknown"
func GetPrincipalID(claims *UnifiedClaims) string

// Machine token helpers
func GetApplicationID(claims *UnifiedClaims) string      // azp or appid
func GetServicePrincipalID(claims *UnifiedClaims) string // oid or fallback
func HasRole(claims *UnifiedClaims, role string) bool     // Generic role checking
func HasApplicationRole(claims *UnifiedClaims, role string) bool // For machine tokens only
func HasUserRole(claims *UnifiedClaims, role string) bool  // For user tokens only
func GetIdentity(claims *UnifiedClaims) string // Unified logging identity

// Context extraction
func ExtractMachineContext(claims *UnifiedClaims) *MachineContext

// Token extraction
func ExtractBearerTokenFromGinContext(c *gin.Context, headerName string) (string, error) // Extract token string from header
```

### Middleware API

```go
// Pre-configured middleware
func NewEntraMiddleware(hmacSecret []byte, logger *zap.Logger) (gin.HandlerFunc, error)

// Custom middleware
func UnifiedJWTMiddleware(config MiddlewareConfig) gin.HandlerFunc
func MachineTokenMiddleware(validator TokenValidator, logger *zap.Logger) gin.HandlerFunc

// Configuration
func DefaultMiddlewareConfig(validator TokenValidator, logger *zap.Logger) MiddlewareConfig

// Context helpers
func GetUserContext(c *gin.Context) *UserContext
func GetMachineContext(c *gin.Context) *MachineContext
```

### Configuration

```go
type Config struct {
    Method SigningMethod // SigningHMAC or SigningPublicKey
    Secret []byte           // For HMAC validation
    JWKSConfig *JWKSConfig  // For JWKS validation
    
    // Optional validation constraints
    RequiredIssuer   string   `json:"required_issuer,omitempty"`
    RequiredAudience []string `json:"required_audience,omitempty"`
}

type JWKSConfig struct {
    BaseURL     string        `json:"base_url"`     // e.g., "https://login.microsoftonline.com"
    TenantID    string        `json:"tenant_id,omitempty"` // Optional for static tenant
    KeyCacheTTL time.Duration `json:"key_cache_ttl"`       // Default: 5min
}
```

## Security Features

### Built-in Protections

1. **Algorithm Verification**: Explicit `alg=none` rejection
2. **HTTP Timeouts**: All JWKS requests have 10s timeout
3. **Resource Cleanup**: Proper goroutine lifecycle management
4. **Input Validation**: Validates identifier existence and email formats
5. **Time Validation**: JWT library handles exp, nbf, iat claims automatically

### Optional Validation

```go
config := token.Config{
    // ... other fields ...
    RequiredIssuer:   "https://sts.windows.net/your-tenant/",
    RequiredAudience: []string{"api://your-app-id"},
}
```

## Token Patterns

### User Tokens (EPFL)

- **SCIPER**: `UniqueID` with 6 digits (e.g., "123456")
- **Service Account**: `UniqueID` with M+5 digits (e.g., "M02575")
- **Unknown**: Standard JWT claims without EPFL-specific patterns

### Machine Tokens (Microsoft Entra)

- **Application ID**: `azp` (v2) or `appid` (v1) field - Must be valid UUID format
- **Service Principal**: `oid` field for directory object - Must be valid UUID format
- **App Roles**: `roles` array with application permissions
- **Validation**: Must have `azp`/`appid` + `roles`, no user-specific fields

#### Valid Azure AD ID Formats

Azure AD identifiers follow UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

```go
// Valid App ID patterns
"8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7"  // azp (authorized party)
"ce306f4f-63ea-4ae3-98ce-1dba7572e990"  // appid (application ID)
"4cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a3"  // oid (object ID)

// Invalid patterns (not UUIDs)
"app-67890"
"my-app-id"
"12345"
```

All Azure AD identifiers are UUIDs generated by Microsoft's identity platform. Test cases and production code should use valid UUID patterns to ensure compatibility.

## EPFL-Specific Features

**Important**: This library includes features specific to EPFL's identity system. External users should be aware of these dependencies.

### EPFL Identity Patterns

**IsPerson()** and **IsService()** validate EPFL-specific identifier formats:

```go
// IsPerson - checks for 6-digit SCIPER (EPFL personnel number)
token.IsPerson(claims)  // true if UniqueID matches ^\d{6}$

// IsService - checks for EPFL service account (M + 5 digits)
token.IsService(claims) // true if UniqueID matches ^M\d{5}$
```

**These functions return `false` for non-EPFL tokens**, even if the token is valid.

```go
// Examples of EPFL-specific patterns
claims := token.UnifiedClaims{UniqueID: "123456"} // SCIPER
token.IsPerson(claims)  // true
token.GetUserType(claims) // "person"

claims = token.UnifiedClaims{UniqueID: "M02575"} // Service account
token.IsService(claims)  // true
token.GetUserType(claims) // "service"

// Non-EPFL token
claims = token.UnifiedClaims{UniqueID: "user123"} // Generic user ID
token.IsPerson(claims)  // false
token.IsService(claims) // false
token.GetUserType(claims) // "unknown"
```

### EPFL Organizational Units

The `Units` field contains EPFL organizational hierarchy:

```go
units := []token.Unit{
    {
        ID:       "13030",
        Name:     "EPFL - STI - IEL - GR-FR",
        CF:       "13030",
        Path:     "/epfl/sti/iel/gr-fr",
        Children: []string{"13031", "13032"},
    },
}
```

- **ID**: Unit identifier (numeric string)
- **Name**: Display name with full hierarchy
- **CF**: Cost center identifier for accounting (Centre Financier)
- **Path**: Hierarchical path for nested lookups
- **Children**: Direct child unit IDs

**For non-EPFL deployments**: These fields will be empty. Consider extending `UnifiedClaims` with your own institution-specific fields.

### Claims Validation

The `UnifiedClaims.Validate()` method performs application-specific validation:

```go
// Validation checks:
// 1. At least one identifier exists (UniqueID, Subject, or Audience)
// 2. Email format is valid (if present)
//
// Note: JWT time claims (exp, nbf, iat) are validated by the JWT library
claims := token.UnifiedClaims{Email: "invalid-email"}
err := claims.Validate()
// Error: "claims validation: invalid email format: invalid-email (field: email)"
```

**For external users**: You can extend validation with your own institution-specific logic if needed.

### Error Handling

The package follows consistent error handling patterns:

1. **ValidationError**: Used for all token validation failures
   - Provides structured context and field information
   - Allows error unwrapping with errors.Is()

2. **Plain errors**: Used for configuration/programming errors
   - Examples: nil validator, missing config

3. **Sentinel errors**: Defined for common error conditions
   - Always wrapped with NewValidationError
   - Enables error identity checking with errors.Is()

```go
// Understanding Error Wrapping with NewValidationError
//
// Consider this code from the package:
//
// // In errors.go - Define sentinel error
// var ErrTokenExpired = errors.New("token has expired")
//
// // In token_validation.go - Validate expiration
// if u.ExpiresAt != nil && u.ExpiresAt.Time.Before(time.Now()) {
//     return NewValidationError(
//         fmt.Errorf("%w at %v", ErrTokenExpired, u.ExpiresAt.Time),
//         "claims validation",
//         "exp",
//     )
// }
//
// This approach provides several benefits:
//
// 1. Error Identity Preservation:
//    - The %w verb wraps ErrTokenExpired while preserving its identity
//    - This allows callers to use errors.Is(err, ErrTokenExpired)
//    - Without wrapping, custom context would break error checking
//
// 2. Rich Context for Debugging:
//    - ValidationError adds source context ("claims validation")
//    - Field information helps pinpoint which field failed ("exp")
//    - Timestamp details help diagnose timing issues
//
// 3. Consistent Error Handling Pattern:
//    - All validation errors follow the same structure
//    - Error handling code can rely on unwrapping
//    - Middleware can extract error details for logging/responses
```

```go
// Error handling example
import (
    "errors"
    "fmt"
    "github.com/epfl-si/go-toolbox/token/v2"
)

func handleTokenValidation(tokenStr string) {
    // Validate token
    claims, err := validator.ValidateToken(tokenStr)
    if err != nil {
        // Method 1: Check specific error types via errors.Is()
        // This works because sentinel errors are wrapped, not replaced
        switch {
        case errors.Is(err, token.ErrTokenExpired):
            fmt.Println("Please obtain a new token, yours has expired")
        case errors.Is(err, token.ErrTokenNotYetValid):
            fmt.Println("Token not valid yet, check server clock skew")
        case errors.Is(err, token.ErrInvalidSignature):
            fmt.Println("Invalid token signature")
        }

        // Method 2: Access structured error fields via errors.As()
        var validationErr *token.ValidationError
        if errors.As(err, &validationErr) {
            fmt.Printf("Validation failed in: %s\n", validationErr.Context)
            if validationErr.Field != "" {
                fmt.Printf("Problem field: %s\n", validationErr.Field)
            }
            // Log the wrapped error for internal debugging
            fmt.Printf("Original error: %v\n", validationErr.Err)
        }
        
        return
    }
    
    // Process valid token...
}
```

### Generic Alternative Usage

If you need generic JWT validation without EPFL-specific features:

```go
// Use the validation API without EPFL-specific functions
validator, _ := token.NewGenericValidator(config, logger)
claims, _ := validator.ValidateToken(tokenString)

// Use standard JWT claims instead of EPFL helpers
userID := claims.Subject // Instead of GetPrincipalID()
userType := "generic"     // Instead of GetUserType()

// Skip IsPerson()/IsService() - use your own classification logic
```

## Testing

```bash
# Run all tests
go test ./... -v

# Run with real Microsoft Entra tokens (slow)
SLOW_TESTS=1 go test ./... -v

# Check coverage
go test ./... -cover
```

All tests pass with the clean implementation and demonstrate proper usage patterns.

## License

MIT License - See LICENSE file for details.
