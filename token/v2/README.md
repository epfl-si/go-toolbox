# Token v2 - Clean JWT Token Validation Library

A modern, clean JWT token validation library with support for both HMAC and JWKS (RS256/ES256) token validation. This is the v2 clean refactor with no backward compatibility constraints.

## Features

- **Clean Modern API**: No legacy cruft, security-first design
- **Dual Validation**: HMAC (HS256) and JWKS (RS256/ES256) support  
- **Auto-Detection**: Automatically chooses validation method based on token algorithm
- **Security Hardened**: Built-in `alg=none` protection, configurable issuer/audience validation
- **Production Ready**: HTTP timeouts, goroutine lifecycle management, proper resource cleanup
- **Machine Token Support**: Full support for Microsoft Entra ID application tokens
- **Gin Middleware**: Ready-to-use middleware for web applications
- **Type Safety**: Strong typing with proper context extraction helpers

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
    router.Use(middleware) // or customMiddleware
    
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
- ✅ Adding custom validation logic (rate limiting, time windows, business rules)
- ✅ Secret rotation periods
- ✅ Multi-tenant with different validation requirements
- ✅ Graceful fallback between validation methods
- ❌ Simple HMAC + JWKS auto-detection (use GenericValidator instead)

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
// Generic validator with auto-detection
func NewGenericValidator(config Config, logger *zap.Logger) (*GenericValidator, error)

// Specific validators
func NewHMACValidator(secret []byte, logger *zap.Logger, config Config) *HMACValidator
func NewJWKSValidator(baseURL, tenantID string, cacheTTL time.Duration, logger *zap.Logger) *JWKSValidator
func NewJWKSValidatorWithClient(baseURL, tenantID string, cacheTTL time.Duration, logger *zap.Logger, client *http.Client, config Config) *JWKSValidator

// Validation interface
type TokenValidator interface {
    ValidateToken(tokenString string) (*UnifiedClaims, error)
}
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
func HasApplicationRole(claims *UnifiedClaims, role string) bool
func GetIdentity(claims *UnifiedClaims) string // Unified logging identity

// Context extraction
func ExtractMachineContext(claims *UnifiedClaims) *MachineContext
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
4. **Input Validation**: Validates UniqueID patterns, email formats
5. **Time Validation**: Checks exp, nbf, iat claims

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
// ✅ Valid App ID patterns
"8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7"  // azp (authorized party)
"ce306f4f-63ea-4ae3-98ce-1dba7572e990"  // appid (application ID)
"4cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a3"  // oid (object ID)

// ❌ Invalid patterns (not UUIDs)
"app-67890"     // Not a valid Azure AD App ID
"my-app-id"     // Not a valid Azure AD App ID
"12345"         // Not a valid Azure AD App ID
```

All Azure AD identifiers are UUIDs generated by Microsoft's identity platform. Test cases and production code should use valid UUID patterns to ensure compatibility.

## EPFL-Specific Features

⚠️ **Important**: This library includes features specific to EPFL's identity system. External users should be aware of these dependencies.

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

### UniqueID Validation

The `UnifiedClaims.Validate()` method enforces EPFL UniqueID patterns:

```go
claims := token.UnifiedClaims{UniqueID: "abc123"} // Invalid pattern
err := claims.Validate()
// Error: "invalid uniqueid format: abc123 - must be 6 digits (SCIPER) or M+5digits (service)"
```

**For external users**: You may need custom validation logic or modify the patterns in `token_validation.go` for your identifier formats.

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