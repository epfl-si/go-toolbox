# Authorization Package

## Overview

The `authorization` package provides a flexible, production-ready authorization system for Go applications built with Gin. It implements a permission model that supports:

- **Role-Based Access Control (RBAC)**: Map Active Directory groups to internal roles with specific permissions
- **Unit-Scoped Permissions**: Fine-grained access control tied to organizational units
- **Machine-to-Machine Authorization**: Support for service principals with unit-level access restrictions
- **Two-Tier Evaluation**: Global role bypass for administrators, unit-scoped permissions for regular users and machines
- **Composable Resource Enhancement**: Flexible system to extract and enrich authorization context from HTTP requests

Works seamlessly with [`github.com/epfl-si/go-toolbox/token/v2`](../token/v2) for JWT authentication. The token package handles JWT validation and claims extraction, while authorization handles permission evaluation


## Core Concepts

### Authorization Flow

Authorization decisions follow a **two-tier evaluation model**:

#### Tier 1: Global Role Bypass
- Checks if the user/machine has a global role with the required permission
- If found, **grants access immediately** (bypasses unit checks)
- Use case: Administrators who need access to all resources

#### Tier 2: Unit-Scoped Permissions
- Only evaluated if Tier 1 fails
- Requires **BOTH** conditions:
  1. User/machine has a role with unit-scoped permission
  2. Target resource's unit is in the user/machine's accessible units list
- Use case: Unit admins who can only manage their unit's resources

#### Example Scenarios

**User with roles `["admin"]` and units `["16000"]`:**
- Accessing unit "16000": GRANTED (via Tier 1 global bypass)
- Accessing unit "99999": GRANTED (via Tier 1 global bypass)

**User with roles `["unit.admin"]` and units `["16000"]`:**
- Accessing unit "16000": GRANTED (via Tier 2 unit-scoped)
- Accessing unit "99999": DENIED (not in accessible units)

## Components

### 1. AuthContext

Represents the authenticated identity (user or machine) making the request.

Abstracts away the differences between human users and service principals, allowing the authorization system to work uniformly with both.

**Key types**:
- `UserAuthContext`: Human users identified by AD groups, organizational units
- `MachineAuthContext`: Service principals identified by client ID, roles, and allowed units

```go
type AuthContext interface {
    GetIdentifier() string    // User ID or Service Principal ID
    GetClientID() string       // Application/client ID
    GetGroups() []string       // AD groups (users) or app roles (machines)
    GetUnits() []string        // Organizational units
    IsUser() bool
    IsMachine() bool
    GetRoles() []string        // Internal roles
}
```

### 2. Permission

Represents a required capability with resource type and action.

Provides a structured way to express "what" someone wants to do, enabling fine-grained access control beyond simple role membership.

```go
type Permission struct {
    Resource string // "app", "unit", "secret", "system"
    Action   string // "read", "write", "delete", "admin"
}

// Predefined permissions
var (
    AppRead   = Permission{Resource: "app", Action: "read"}
    AppWrite  = Permission{Resource: "app", Action: "write"}
    AppDelete = Permission{Resource: "app", Action: "delete"}
    UnitRead  = Permission{Resource: "unit", Action: "read"}
    UnitWrite = Permission{Resource: "unit", Action: "write"}
    // ... more
)
```

### 3. ResourceContext

Contains information about the resource being accessed (e.g., which unit owns it).

Enables context-aware authorization decisions. Without knowing which unit a resource belongs to, unit-scoped permissions cannot be evaluated.

```go
type ResourceContext map[string]string

// Example resource contexts
resource := ResourceContext{
    "unitID": "16000",                          // Unit-scoped resource
    "appID": "app-123",                         // Application identifier
    "machineUnits": "16000,16001,16002",       // Machine's allowed units
}
```

### 4. ResourceEnhancer

*Extracts and enriches resource context from HTTP requests and external sources.

Authorization information is scattered across URL parameters, request bodies, headers, and databases. Enhancers provide a composable pipeline to gather all necessary context before making authorization decisions.

```go
type ResourceEnhancer interface {
    Enhance(ctx context.Context, resource ResourceContext) (ResourceContext, error)
    Name() string // For logging and debugging
}
```

**Built-in enhancers**:
- `ParamEnhancer`: Extracts URL path parameters (e.g., `/apps/:id`)
- `QueryEnhancer`: Extracts query parameters (e.g., `?unit=16000`)
- `BodyEnhancer`: Extracts data from JSON request body
- `HeaderEnhancer`: Extracts HTTP headers
- `ChainEnhancer`: Composes multiple enhancers in sequence

### 5. PolicyEvaluator

Makes the actual authorization decision based on AuthContext, Permission, and ResourceContext.

Encapsulates the complex two-tier evaluation logic, including global bypasses, unit-scoped checks, and machine-specific rules.

```go
type PolicyEvaluator struct {
    config *Config
    log    *zap.Logger
}

// Evaluate returns (authorized bool, reason string)
func (e *PolicyEvaluator) Evaluate(
    authCtx AuthContext,
    permission Permission,
    resource ResourceContext,
) (bool, string)
```

### 6. Service

High-level API for creating middleware and performing authorization checks.

Simplifies common use cases by providing pre-configured middleware factories and utility methods.

```go
type Service struct {
    authorizer *SimpleAuthorizer
    log        *zap.Logger
}

// Create middleware for different scenarios
func (s *Service) RequirePermission(permission Permission, enhancer ResourceEnhancer) gin.HandlerFunc
func (s *Service) RequireRole(role string) gin.HandlerFunc
func (s *Service) RequireAppAccess(action string, enhancer ResourceEnhancer) gin.HandlerFunc

// Utility methods for programmatic checks
func (s *Service) CanAccess(c *gin.Context, permission Permission, resource ResourceContext) (bool, error)
func (s *Service) HasRole(c *gin.Context, role string) (bool, error)
```

### 7. Config

Stores the authorization policy configuration (role-to-permission mappings, group mappings, etc.).

Separates policy definition from policy enforcement, allowing runtime configuration changes and environment-specific policies.

```go
type Config struct {
    RolePermissions map[string][]Permission // Global permissions
    GroupMappings   map[string][]string     // AD group -> role mappings
    MachineUnits    map[string][]string     // Client ID -> allowed units
    UnitScopedRoles map[string][]Permission // Unit-scoped roles
}
```

## Public Interfaces

### Quick Integration Example

Here's a minimal working example showing token/v2 integration:

```go
import (
    "github.com/epfl-si/go-toolbox/authorization"
    "github.com/epfl-si/go-toolbox/authorization/enhancers"
    token "github.com/epfl-si/go-toolbox/token/v2"
    "github.com/gin-gonic/gin"
)

func main() {
    router := gin.New()
    logger, _ := zap.NewProduction()

    // 1. Setup token validation
    validator, _ := token.NewGenericValidator(token.Config{
        Secret: []byte("your-secret"),
    }, logger)

    // 2. Setup authorization
    config := authorization.GetDefaultConfig()
    authService := authorization.NewService(
        authorization.NewSimpleAuthorizer(
            authorization.NewPolicyEvaluator(config, logger),
            logger,
        ),
        logger,
    )

    // 3. Create middleware chain
    tokenMw := token.UnifiedJWTMiddleware(token.MiddlewareConfig{
        Validator: validator,
        Logger:    logger,
    })

    // AuthContext extractor middleware
    extractor := NewAuthContextExtractor(config, nil, logger)
    authContextMw := extractor.ExtractAuthContext()

    // 4. Apply middlewares to routes
    api := router.Group("/api")
    api.Use(tokenMw)         // First: validate token
    api.Use(authContextMw)   // Second: extract AuthContext

    // Use authorization middleware on specific routes
    api.GET("/apps/:id",
        authService.RequirePermission(
            authorization.AppRead,
            enhancers.NewParamEnhancer("id", "appID"),
        ),
        getAppHandler)

    router.Run(":8080")
}

// Simplified AuthContextExtractor for quick start
type AuthContextExtractor struct {
    config *authorization.Config
    log    *zap.Logger
}

func NewAuthContextExtractor(config *authorization.Config, clientToUnits map[string][]string, log *zap.Logger) *AuthContextExtractor {
    return &AuthContextExtractor{config: config, log: log}
}

func (e *AuthContextExtractor) ExtractAuthContext() gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, exists := c.Get("claims")
        if !exists {
            c.Next()
            return
        }

        tokenClaims := claims.(*token.UnifiedClaims)
        var authCtx authorization.AuthContext

        if token.GetTokenType(tokenClaims) == token.TypeMachine {
            authCtx = &authorization.MachineAuthContext{
                ServicePrincipalID: token.GetServicePrincipalID(tokenClaims),
                ClientID:           token.GetApplicationID(tokenClaims),
                Roles:              tokenClaims.Roles,
            }
        } else {
            authCtx = &authorization.UserAuthContext{
                UniqueID: tokenClaims.UniqueID,
                Groups:   tokenClaims.Groups,
            }
        }
        authorization.SetAuthContext(c, authCtx)
        c.Next()
    }
}
```

### Creating an Authorization Service

```go
import (
    "github.com/epfl-si/go-toolbox/authorization"
    "go.uber.org/zap"
)

// Option 1: Use default configuration
config := authorization.GetDefaultConfig()
evaluator := authorization.NewPolicyEvaluator(config, logger)
authorizer := authorization.NewSimpleAuthorizer(evaluator, logger)
service := authorization.NewService(authorizer, logger)

// Option 2: Load from YAML/JSON file
config := authorization.NewConfig()
err := config.LoadFromFile("policy.yaml")
// ... create evaluator, authorizer, service

// Option 3: Build programmatically
config := &authorization.Config{
    RolePermissions: map[string][]authorization.Permission{
        "admin": {
            {Resource: "app", Action: "read"},
            {Resource: "app", Action: "write"},
        },
    },
    UnitScopedRoles: map[string][]authorization.Permission{
        "unit.admin": {
            {Resource: "app", Action: "write"},
        },
    },
    GroupMappings: map[string][]string{
        "APP-PORTAL-ADMINS": {"admin"},
        "DEPT-A-ADMINS":     {"unit.admin"},
    },
}
```

### Creating Middleware

```go
// Basic permission check with URL parameter
unitIDEnhancer := enhancers.NewParamEnhancer("unitid", "unitID")
router.GET("/units/:unitid",
    service.RequirePermission(authorization.UnitRead, unitIDEnhancer),
    handler)

// Application access with database lookup
appEnhancer := CreateAppEnhancer("id", appRepository, logger)
router.DELETE("/apps/:id",
    service.RequirePermission(authorization.AppDelete, appEnhancer),
    handler)

// Extract unit from request body
bodyEnhancer := enhancers.NewBodyEnhancer([]string{"unitID", "unit_id"}, "unitID")
router.POST("/apps",
    service.RequirePermission(authorization.AppWrite, bodyEnhancer),
    handler)

// Chain multiple enhancers
chainEnhancer := enhancers.NewChainEnhancer(
    enhancers.NewParamEnhancer("id", "appID"),
    customDatabaseEnhancer,
    machineUnitEnhancer,
)
router.PUT("/apps/:id",
    service.RequirePermission(authorization.AppWrite, chainEnhancer),
    handler)
```

### Extracting and Storing AuthContext

**Integration with token/v2**: Use the companion `token/v2` package for JWT authentication, with an AuthContext extraction middleware that converts token claims to authorization context.

**You must implement**: An `AuthContextExtractor` struct with an `ExtractAuthContext()` middleware method. This middleware converts `UnifiedClaims` from the token package to `AuthContext` used by the authorization package. Optionally include repository lookups for additional data.

```go
import (
    "context"
    "github.com/epfl-si/go-toolbox/authorization"
    token "github.com/epfl-si/go-toolbox/token/v2"
    "github.com/gin-gonic/gin"
)

// AuthContextExtractor converts token claims to authorization context
type AuthContextExtractor struct {
    config         *authorization.Config
    clientToUnits  map[string][]string // Machine client ID -> allowed units
    log            *zap.Logger
}

func NewAuthContextExtractor(config *authorization.Config, clientToUnits map[string][]string, log *zap.Logger) *AuthContextExtractor {
    return &AuthContextExtractor{
        config:        config,
        clientToUnits: clientToUnits,
        log:           log,
    }
}

// ExtractAuthContext middleware converts UnifiedClaims to AuthContext
func (e *AuthContextExtractor) ExtractAuthContext() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get claims from token middleware
        claimsVal, exists := c.Get("claims")
        if !exists {
            e.log.Debug("No claims found in context")
            c.Next()
            return
        }

        claims := claimsVal.(*token.UnifiedClaims)
        authCtx, err := e.extractFromClaims(c.Request.Context(), claims)
        if err != nil {
            e.log.Warn("Failed to extract auth context", zap.Error(err))
            c.Next()
            return
        }

        // Store for authorization middleware
        authorization.SetAuthContext(c, authCtx)
        c.Next()
    }
}

func (e *AuthContextExtractor) extractFromClaims(ctx context.Context, claims *token.UnifiedClaims) (authorization.AuthContext, error) {
    // Determine token type
    if token.GetTokenType(claims) == token.TypeMachine {
        // Machine token
        allowedUnits := e.clientToUnits[token.GetApplicationID(claims)]

        return &authorization.MachineAuthContext{
            ServicePrincipalID: token.GetServicePrincipalID(claims),
            ClientID:           token.GetApplicationID(claims),
            Groups:             claims.Groups,
            Roles:              claims.Roles,
            AllowedUnits:       allowedUnits,
        }, nil
    }

    // User token - extract units from claims
    units := make([]string, len(claims.Units))
    for i, unit := range claims.Units {
        units[i] = unit.ID
    }

    // Derive roles from groups using policy
    roles := e.config.GetRolesForGroups(claims.Groups)

    return &authorization.UserAuthContext{
        UniqueID: claims.UniqueID,
        ClientID: token.GetApplicationID(claims),
        Groups:   claims.Groups,
        Units:    units,
        Roles:    roles,
    }, nil
}
```

**Note**: For production use with repository lookups (e.g., fetching units from database), see the reference implementation in `md-app-portal-api/internal/api/auth/auth_extractor.go`.

### Programmatic Authorization Checks

```go
func (h *Handler) SomeHandler(c *gin.Context) {
    // Check permission programmatically
    canWrite, err := h.authzService.CanAccess(c,
        authorization.AppWrite,
        authorization.ResourceContext{"unitID": "16000"})
    if err != nil {
        // Handle error
    }
    if !canWrite {
        // User cannot write to this unit
    }

    // Check role membership
    isAdmin, _ := h.authzService.HasRole(c, "admin")

    // Get user's roles
    roles, _ := h.authzService.GetUserRoles(c)
}
```

## Getting Started

**Prerequisites**: This guide uses the companion `github.com/epfl-si/go-toolbox/token/v2` package for JWT authentication. Install both packages:

```bash
go get github.com/epfl-si/go-toolbox/authorization
go get github.com/epfl-si/go-toolbox/token/v2
```

The token/v2 package handles:
- JWT validation (HMAC + JWKS/RS256)
- Token parsing and claims extraction
- User vs machine token detection

The authorization package handles:
- Permission evaluation
- Role-based and unit-scoped access control
- Resource context enrichment

### Step 1: Define Your Policy

Create a `policy.yaml` configuration file:

```yaml
rolePermissions:
  admin:
    - resource: app
      action: read
    - resource: app
      action: write
    - resource: app
      action: delete
    - resource: unit
      action: write

  readonly:
    - resource: app
      action: read

unitScopedRoles:
  unit.admin:
    - resource: app
      action: write
    - resource: app
      action: delete

  app.creator:
    - resource: app
      action: write

groupMappings:
  APP-PORTAL-ADMINS: ["admin"]
  APP-PORTAL-READERS: ["readonly"]
  DEPT-A-ADMINS: ["unit.admin", "app.creator"]

machineUnits:
  "client-id-123": ["16000", "16001"]
  "client-id-456": ["16002"]
```

### Step 2: Initialize the Authorization System

```go
func setupAuthorization(logger *zap.Logger) *authorization.Service {
    // Load configuration
    config := authorization.NewConfig()
    if err := config.LoadFromFile("policy.yaml"); err != nil {
        panic(err)
    }

    // Create the authorization stack
    evaluator := authorization.NewPolicyEvaluator(config, logger)
    authorizer := authorization.NewSimpleAuthorizer(evaluator, logger)
    service := authorization.NewService(authorizer, logger)

    return service
}
```

### Step 3: Create Authentication and AuthContext Middleware

**Using token/v2 package**: Use the companion token package for JWT validation (recommended).

```go
import (
    "time"
    "github.com/epfl-si/go-toolbox/authorization"
    token "github.com/epfl-si/go-toolbox/token/v2"
)

func setupAuthenticationMiddleware(
    authzConfig *authorization.Config,
    secret []byte,
    clientToUnits map[string][]string,
    logger *zap.Logger,
) (tokenMw, authContextMw gin.HandlerFunc) {
    // Configure token validator for HMAC + JWKS
    tokenConfig := token.Config{
        Secret: secret,
        JWKSConfig: &token.JWKSConfig{
            BaseURL:     "https://login.microsoftonline.com",
            KeyCacheTTL: 5 * time.Minute,
        },
    }

    validator, err := token.NewGenericValidator(tokenConfig, logger)
    if err != nil {
        panic(err)
    }

    // First middleware: validates JWT and extracts claims
    tokenMw = token.UnifiedJWTMiddleware(token.MiddlewareConfig{
        Validator: validator,
        Logger:    logger,
    })

    // Second middleware: extracts AuthContext from claims
    extractor := NewAuthContextExtractor(authzConfig, clientToUnits, logger)
    authContextMw = extractor.ExtractAuthContext()

    return tokenMw, authContextMw
}

// AuthContextExtractor implementation
type AuthContextExtractor struct {
    config        *authorization.Config
    clientToUnits map[string][]string
    log           *zap.Logger
}

func NewAuthContextExtractor(config *authorization.Config, clientToUnits map[string][]string, log *zap.Logger) *AuthContextExtractor {
    return &AuthContextExtractor{
        config:        config,
        clientToUnits: clientToUnits,
        log:           log,
    }
}

func (e *AuthContextExtractor) ExtractAuthContext() gin.HandlerFunc {
    return func(c *gin.Context) {
        claimsVal, exists := c.Get("claims")
        if !exists {
            e.log.Debug("No claims found, skipping auth context extraction")
            c.Next()
            return
        }

        claims := claimsVal.(*token.UnifiedClaims)
        var authCtx authorization.AuthContext

        if token.GetTokenType(claims) == token.TypeMachine {
            authCtx = &authorization.MachineAuthContext{
                ServicePrincipalID: token.GetServicePrincipalID(claims),
                ClientID:           token.GetApplicationID(claims),
                Groups:             claims.Groups,
                Roles:              claims.Roles,
                AllowedUnits:       e.clientToUnits[token.GetApplicationID(claims)],
            }
        } else {
            // Extract unit IDs from token claims
            units := make([]string, len(claims.Units))
            for i, unit := range claims.Units {
                units[i] = unit.ID
            }

            // Derive roles from groups
            roles := e.config.GetRolesForGroups(claims.Groups)

            authCtx = &authorization.UserAuthContext{
                UniqueID: claims.UniqueID,
                ClientID: token.GetApplicationID(claims),
                Groups:   claims.Groups,
                Units:    units,
                Roles:    roles,
            }
        }

        authorization.SetAuthContext(c, authCtx)
        c.Next()
    }
}
```

### Step 4: Apply Middleware to Routes

```go
func setupRoutes(
    router *gin.Engine,
    authService *authorization.Service,
    tokenMw, authContextMw gin.HandlerFunc,
    appRepository ApplicationRepository,
    logger *zap.Logger,
) {
    // Public routes (no auth)
    router.GET("/health", healthHandler)

    // Protected routes - apply authentication and authContext middlewares
    api := router.Group("/api/v1")
    api.Use(tokenMw)        // First: validate JWT token
    api.Use(authContextMw)  // Second: extract AuthContext from claims

    // Simple role-based protection
    api.GET("/admin", authService.RequireRole("admin"), adminHandler)

    // Permission-based with unit scope from URL parameter
    unitEnhancer := enhancers.NewParamEnhancer("unitid", "unitID")
    api.GET("/units/:unitid/apps",
        authService.RequirePermission(authorization.AppRead, unitEnhancer),
        listAppsHandler)

    // Permission-based with unit from request body
    bodyEnhancer := enhancers.NewBodyEnhancer([]string{"unitID"}, "unitID")
    api.POST("/apps",
        authService.RequirePermission(authorization.AppWrite, bodyEnhancer),
        createAppHandler)

    // Complex enhancement chain with database lookup
    appEnhancer := createComplexEnhancer(appRepository, logger)
    api.DELETE("/apps/:id",
        authService.RequirePermission(authorization.AppDelete, appEnhancer),
        deleteAppHandler)
}
```

### Step 5: Implement Custom Enhancers

**You should implement**: Custom enhancers for database lookups or application-specific logic.

```go
// Custom enhancer that looks up unit from database
type AppDatabaseEnhancer struct {
    repo ApplicationRepository
    log  *zap.Logger
}

func (e *AppDatabaseEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
    result := resource.Clone()

    // If appID is present but unitID is not, resolve from database
    if appID, ok := resource["appID"]; ok && appID != "" {
        if _, hasUnit := resource["unitID"]; !hasUnit {
            unitID, err := e.repo.GetUnitByAppID(ctx, appID)
            if err != nil {
                e.log.Warn("Failed to resolve unit", zap.Error(err))
                return result, nil // Don't fail, just continue
            }
            result["unitID"] = unitID
        }
    }

    return result, nil
}

func (e *AppDatabaseEnhancer) Name() string {
    return "AppDatabaseEnhancer"
}

// Use it in a chain
func createComplexEnhancer(repo ApplicationRepository, log *zap.Logger) authorization.ResourceEnhancer {
    return enhancers.NewChainEnhancer(
        enhancers.NewParamEnhancer("id", "appID"),     // Extract from URL
        &AppDatabaseEnhancer{repo: repo, log: log},    // Lookup in database
        createMachineUnitEnhancer(log),                // Add machine units
    )
}

// Machine unit enhancer for M2M authorization
func createMachineUnitEnhancer(log *zap.Logger) authorization.ResourceEnhancer {
    clientToUnits := map[string][]string{
        "client-id-123": {"16000", "16001"},
        "client-id-456": {"16002"},
    }

    return &MachineUnitEnhancer{
        clientToUnits: clientToUnits,
        log:           log,
    }
}
```

### Complete Example

For a full production-ready implementation, see the `md-app-portal-api` reference implementation:

**Key files:**
- **Token validation setup**: `md-app-portal-api/internal/api/routes.go:59-116`
  - Shows token validator with chained test validators
  - Demonstrates clientToUnits mapping configuration

- **AuthContext extraction**: `md-app-portal-api/internal/api/auth/auth_extractor.go`
  - `AuthContextExtractor` struct and `ExtractAuthContext()` middleware
  - Handles both machine and user tokens
  - Includes repository fallback for fetching units from database

- **Authorization middleware**: `md-app-portal-api/internal/api/auth/middleware.go`
  - `AuthorizationMiddleware` wrapper pattern
  - Integrates `ExtractAuthContext()` middleware
  - Provides `RequirePermission()` convenience methods

- **Route configuration**: `md-app-portal-api/internal/api/routes.go:133-232`
  - Shows middleware application pattern: `token.UnifiedJWTMiddleware()` → `ExtractAuthContext()`
  - Demonstrates permission-based authorization with enhancers

- **Custom enhancers**: `md-app-portal-api/internal/api/auth/enhancers/app_enhancers.go`
  - `MachineUnitEnhancer` for M2M authorization
  - `AppEnhancer` for database lookups
  - `CreateAppEnhancer` for chained enhancement

This implementation demonstrates the complete integration pattern with token/v2 for authentication and the authorization package for permission evaluation.

## Key Design Decisions

1. **Two-Tier Evaluation**: Balances administrative convenience (global bypass) with security (unit-scoped restrictions)
2. **Enhancer Pattern**: Separates resource extraction from authorization logic, enabling reusable, testable components
3. **Interface-Based Design**: AuthContext abstracts users and machines, allowing uniform treatment and easy extension
4. **Fail-Open Enhancers**: Enhancers that fail (e.g., database lookup errors) don't block requests but log warnings, preventing cascading failures
5. **Context Propagation**: Uses both `gin.Context` and `context.Context` for maximum compatibility with middleware patterns

## Testing

The package includes comprehensive tests:
- `authorizer_test.go`: Core authorization logic
- `evaluator_test.go`: Policy evaluation scenarios
- `config_test.go`: Configuration parsing
- `middleware_test.go`: HTTP middleware behavior
- `enhancers/*_test.go`: Individual enhancer behavior

Run tests with:
```bash
go test ./...
```
