# Token Package

The `token` package provides JWT token handling utilities for EPFL microservices, supporting both modern unified token validation and legacy token formats.

## Overview

This package handles JWT tokens in two ways:
- **Unified Approach** (recommended): Supports both HMAC and JWKS validation with automatic detection
- **Legacy Approach** (deprecated): Simple HMAC-only validation with basic claims

The unified approach automatically detects token types and validates them appropriately, making it suitable for both local development (HMAC tokens) and production environments (Entra ID JWKS tokens).

## Quick Start

### Basic Usage (Recommended)

```go
package main

import (
    "time"
    
    "github.com/epfl-si/go-toolbox/token"
    jwt "github.com/golang-jwt/jwt/v5"
    "go.uber.org/zap"
)

func main() {
    // Create claims for a person
    claims := token.UnifiedClaims{
        UniqueID: "123456", // SCIPER for people
        Name:     "John Doe",
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   "john.doe@epfl.ch",
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
        },
    }

    // Create and sign token
    t := token.NewUnified(claims)
    tokenString, err := t.Sign([]byte("your-secret"))
    if err != nil {
        panic(err)
    }

    // Parse token back
    parsedClaims, err := token.ParseUnified(tokenString, []byte("your-secret"))
    if err != nil {
        panic(err)
    }

    fmt.Printf("User ID: %s\n", token.GetUserID(parsedClaims))
    fmt.Printf("User Type: %s\n", token.GetUserType(parsedClaims))
}
```

### Basic Gin Middleware

```go
package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/epfl-si/go-toolbox/token"
    "go.uber.org/zap"
)

func main() {
    logger := zap.NewExample()
    
    // Configure token validation
    config := token.Config{
        Method: token.ValidationHMAC,
        Secret: []byte("your-secret-key"),
    }
    
    // Create validator and middleware config
    validator, err := token.NewGenericValidator(config, logger)
    if err != nil {
        panic(err)
    }
    middlewareConfig := token.DefaultMiddlewareConfig(validator, logger)

    // Setup Gin with unified token middleware
    r := gin.New()
    r.Use(token.UnifiedJWTMiddleware(middlewareConfig))

    r.GET("/protected", func(c *gin.Context) {
        // Access parsed claims
        claimsInterface, exists := c.Get("claims")
        if !exists {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Token claims not found"})
            return
        }
        claims := claimsInterface.(*token.UnifiedClaims)
        userID := c.GetString("user_id")
        
        c.JSON(200, gin.H{
            "message":   "Hello from protected route",
            "user_id":   userID,
            "is_person": token.IsPerson(claims),
            "is_service": token.IsService(claims),
            "name":      claims.Name,
        })
    })

    r.Run(":8080")
}
```

```markdown

### Authentication Gin Handler

The package provides a Gin unified login handler for issuing JWT tokens:

```go
// Create an authenticator that implements UnifiedAuthenticater
type MyAuthenticator struct {
    // your fields here
}

func (a *MyAuthenticator) Authenticate(login, pass string) (*token.UnifiedClaims, error) {
    // Your authentication logic here
    return &token.UnifiedClaims{
        UniqueID: "123456",
        Name:     "John Doe",
        Email:    "john.doe@epfl.ch",
    }, nil
}

// Setup the login handler
secret := []byte("your-secret-key")
auth := &MyAuthenticator{}
loginHandler := token.UnifiedPostLoginHandler(logger, auth, secret)

// Use in your Gin router
r.POST("/login", loginHandler)
```

The handler:
- Accepts POST requests with "login" and "pass" form fields
- Uses the provided authenticator to validate credentials
- Returns a JWT token on successful authentication
- Supports both person and service account tokens
```

### Advanced Gin Middleware with JWKS

For production applications using Entra ID tokens:

```go
package main

import (
    "net/http"
    "time"
    "github.com/gin-gonic/gin"
    "github.com/epfl-si/go-toolbox/token"
    "go.uber.org/zap"
)

func main() {
    logger := zap.NewProduction()
    
    // Configure JWKS validation for production
    config := token.Config{
        Method: token.ValidationJWKS,
        JWKSConfig: &token.JWKSConfig{
            BaseURL:     "https://login.microsoftonline.com",
            KeyCacheTTL: 1 * time.Hour,
        },
        CacheEnabled: true,
        CacheTTL:     5 * time.Minute,
    }
    
    // Create validator and middleware config
    validator, err := token.NewGenericValidator(config, logger)
    if err != nil {
        panic(err)
    }
    middlewareConfig := token.DefaultMiddlewareConfig(validator, logger)
    
    r := gin.New()
    r.Use(token.UnifiedJWTMiddleware(middlewareConfig))
    
    r.GET("/protected", func(c *gin.Context) {
        // Access parsed claims
        claimsInterface, exists := c.Get("claims")
        if !exists {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Token claims not found"})
            return
        }
        claims := claimsInterface.(*token.UnifiedClaims)
        userID := c.GetString("user_id")
        
        c.JSON(200, gin.H{
            "user_id": userID,
            "user_type": c.GetString("user_type"),
            "is_person": token.IsPerson(claims),
            "is_service": token.IsService(claims),
            "groups": claims.Groups,
            "name": claims.Name,
        })
    })
    
    r.Run(":8080")
}
```

## Unified Token Validation

### Claims Structure

The `UnifiedClaims` struct supports both local HMAC tokens and Entra ID JWKS tokens:

```go
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
```

**Key Points:**
- `UniqueID` can contain different identifier patterns:
  - **Persons**: 6-digit SCIPER pattern (`^\d{6}$`, e.g., "123456")  
  - **Service accounts**: M + 5-digit SCIPER pattern (`^M\d{5}$`, e.g., "M02575")
- **Other tokens**: Use standard JWT claims (`Subject`, `Audience`)

### Configuration

#### HMAC Validation

```go
config := token.Config{
    Method: token.ValidationHMAC,
    Secret: []byte("your-secret-key"),
}
```

#### JWKS Validation (Entra)

```go
config := token.Config{
    Method: token.ValidationJWKS,
    JWKSConfig: &token.JWKSConfig{
        BaseURL:     "https://login.microsoftonline.com",
        KeyCacheTTL: 5 * time.Minute,
    },
    CacheEnabled: true,
    CacheTTL:     5 * time.Minute,
}
```

### Generic Validator

The `GenericValidator` automatically detects token types and validates appropriately:

```go
// Create validator
validator, err := token.NewGenericValidator(config, logger)
if err != nil {
    log.Fatal(err)
}

// Validate token - method determined automatically
claims, err := validator.ValidateToken(tokenString)
if err != nil {
    log.Printf("Token validation failed: %v", err)
    return
}

// Extract user information
userID := token.GetUserID(claims)   // Works for all token types
isPerson := token.IsPerson(claims)  // true if UniqueID matches 6-digit SCIPER pattern
isService := token.IsService(claims) // true if UniqueID matches M+5digits SCIPER pattern
```

### Automatic Detection

The validator automatically determines validation method based on the JWT algorithm header:
- `HS256` tokens -> HMAC validation with shared secret
- `RS256`/`ES256` tokens -> JWKS validation with public keys

### Person vs Service Detection

Token type is determined by pattern matching:
- **Person**: `UniqueID` matches 6-digit SCIPER pattern (`^\d{6}$`, e.g., "123456")
- **Service Account**: `UniqueID` matches M + 5-digit SCIPER pattern (`^M\d{5}$`, e.g., "M02575")
- **Other/Unknown**: Doesn't match either pattern, uses standard JWT claims

### Helper Functions

```go
// Extract user ID (works for both persons and services)
userID := token.GetUserID(claims)

// Check token type
isPerson := token.IsPerson(claims)     // true if UniqueID matches 6-digit SCIPER
isService := token.IsService(claims)   // true if UniqueID matches M+5digits SCIPER
```

## Legacy Token Support (Deprecated)

⚠️ **The legacy approach is deprecated and will be removed in a future version. Please migrate to the unified approach.**

### Legacy Claims Structure

```go
type CustomClaims struct {
    Sciper string `json:"sciper"`
    jwt.RegisteredClaims
}
```

### Legacy Usage

```go
// Legacy way (deprecated)
claims := token.CustomClaims{
    Sciper: "123456",
    RegisteredClaims: jwt.RegisteredClaims{
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
    },
}

token := token.New(claims)
tokenString, err := token.Sign([]byte("secret"))
```

### Legacy Middleware

```go
// Legacy middleware (deprecated - use UnifiedJWTMiddleware instead)
r.Use(token.GinMiddleware([]byte("secret")))

r.GET("/protected", func(c *gin.Context) {
    tokenInterface, exists := c.Get("token")
    if !exists {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Token not found"})
        return
    }
    token := tokenInterface.(*token.Token)
    claims := token.Claims()
    sciper := claims["sciper"].(string)
    
    c.JSON(200, gin.H{"sciper": sciper})
})
```

## Migration Guide

### Step 1: Convert Claims

Replace `CustomClaims` usage with `UnifiedClaims`:

```go
// Before (deprecated)
oldClaims := token.CustomClaims{
    Sciper: "123456",
    RegisteredClaims: jwt.RegisteredClaims{
        Subject: "user@epfl.ch",
    },
}

// After (recommended)
newClaims := token.UnifiedClaims{
    UniqueID: "123456", // Map sciper to uniqueid
    RegisteredClaims: jwt.RegisteredClaims{
        Subject: "user@epfl.ch",
    },
}
```

### Step 2: Use Conversion Helpers

For gradual migration, use the built-in conversion functions:

```go
// Convert legacy claims to unified
legacyClaims := token.CustomClaims{Sciper: "123456"}
unifiedClaims := legacyClaims.ToUnifiedClaims()

// Convert back if needed for compatibility
backToLegacy := unifiedClaims.ToCustomClaims()
```

### Step 3: Update Token Creation

```go
// Before
token := token.New(customClaims)

// After
token := token.NewUnified(unifiedClaims)
```

### Step 4: Update Token Parsing

```go
// Before
token, err := token.Parse(tokenString, secret)

// After  
claims, err := token.ParseUnified(tokenString, secret)
```

### Step 5: Update Middleware

```go
// Before (deprecated)
r.Use(token.GinMiddleware(secret))

// Now (recommended)
config := token.Config{
    Method: token.ValidationHMAC,
    Secret: secret,
}
validator, _ := token.NewGenericValidator(config, logger)
middlewareConfig := token.DefaultMiddlewareConfig(validator, logger)
r.Use(token.UnifiedJWTMiddleware(middlewareConfig))

// This sequence being tedious, see the Validation Middleware section
// for a simpler setup

```

### Step 6: Update Route Handlers

```go
// Before
r.GET("/protected", func(c *gin.Context) {
    tokenInterface, exists := c.Get("token")
    if !exists {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Token not found"})
        return
    }
    token := tokenInterface.(*token.Token)
    sciper := token.Claims()["sciper"].(string)
    c.JSON(200, gin.H{"sciper": sciper})
})

// After
r.GET("/protected", func(c *gin.Context) {
    claimsInterface, exists := c.Get("claims")
    if !exists {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Token claims not found"})
        return
    }
    claims := claimsInterface.(*token.UnifiedClaims)
    userID := c.GetString("user_id")
    
    c.JSON(200, gin.H{
        "user_id": userID,
        "is_person": token.IsPerson(claims),
        "is_service": token.IsService(claims),
        "unique_id": claims.UniqueID,
    })
})
```

### Step 7: Update Login Handlers

```go
// Before (deprecated)
handler := token.PostLoginHandler(logger, auth, secret)

// Now (recommended)
handler := token.UnifiedPostLoginHandler(logger, auth, secret)
```

## Advanced Usage

### Custom Claims

Add EPFL-specific claims to tokens:

```go
claims := token.UnifiedClaims{
    UniqueID: "123456",
    Name:     "John Doe",
    Email:    "john.doe@epfl.ch",
    Groups:   []string{"EPFL-SI", "ADMINS"},
    Scopes:   []string{"read", "write"},
    Units: []token.Unit{
        {
            ID:   "12345",
            Name: "EPFL-SI",
            CF:   "1234",
            Path: "EPFL VPO-SI",
        },
    },
    Roles: []string{"admin", "user"},
}
```

### Service Account Tokens

```go
// Service account token
claims := token.UnifiedClaims{
    UniqueID: "M02575", // Service account pattern
    RegisteredClaims: jwt.RegisteredClaims{
        Subject:  "service01@epfl.ch",
        Audience: []string{"target-service"},
    },
}

// Will be detected as service account
isService := token.IsService(&claims) // true
isPerson := token.IsPerson(&claims)   // false
userID := token.GetUserID(&claims)    // "M02575"
```

### Validation Configuration

```go
// Development configuration
devConfig := token.Config{
    Method:       token.ValidationHMAC,
    Secret:       []byte("dev-secret"),
    CacheEnabled: false,
}

// Production configuration
prodConfig := token.Config{
    Method: token.ValidationJWKS,
    JWKSConfig: &token.JWKSConfig{
        BaseURL:     "https://login.microsoftonline.com",
        KeyCacheTTL: 5 * time.Minute,
    },
    CacheEnabled: true,
    CacheTTL:     5 * time.Minute,
}
```

### Validation middleware

For convenience there's an helper to generate a middleware that handle both Entra and local generated HMAC token:

```go
// Create middleware that handles both Entra ID and local tokens
middleware, err := token.NewEntraMiddleware(
    []byte("local-hmac-secret"),
    logger,
)
if err != nil {
    log.Fatal(err)
}

// Use in your Gin router
r.Use(middleware)
```

This middleware:
- Automatically validates Entra ID tokens using JWKS
- Falls back to HMAC validation for local development tokens
- Configures optimal cache settings for JWKS keys
- Provides unified claims access in handlers

## Testing

Run tests with:

```bash
cd go-toolbox/token
go test -v
```