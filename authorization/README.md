
# Authorization Module

## Purpose and Goals

The `authorization` module provides a flexible, decoupled, and extensible authorization system for the application. It abstracts authorization logic into an independent module that can be reused across different parts of the application while maintaining clear separation of concerns.

### Key Goals

- **Separation of Concerns**: Decouple authorization logic from business logic and HTTP handling
- **Dual Authentication Support**: Handle both human users (via OAuth2) and service principals (M2M tokens)
- **Role-Based Access Control (RBAC)**: Implement a clean role-permission model with group mappings
- **Resource-Aware Authorization**: Support context-aware decisions based on resource attributes
- **Extensibility**: Allow applications to customize and extend authorization behavior
- **Testability**: Provide clean interfaces that are easy to mock and test
- **Modularity**: Allow extraction as a standalone module with no dependencies on other internal packages

## Design Principles and Technical Choices

### 1. Interface-Based Design

The module is built around well-defined interfaces rather than concrete implementations:
- [`Authorizer`](authorizer.go:11-18): Core authorization contract
- [`AuthContext`](context.go:5-14): Abstraction for user/machine identity
- [`ResourceEnhancer`](enhancer.go): Interface for extracting and enriching resource context

This allows applications to provide custom implementations while maintaining a consistent API.

### 2. RBAC with Group Mappings

The system uses a two-level mapping approach:
- **Groups → Roles**: AD groups are mapped to internal roles
- **Roles → Permissions**: Roles are granted specific permissions

**Why?** This provides flexibility - AD groups can be reorganized without changing permission definitions, and roles can be reused across different group configurations.

### 3. Context-Aware Authorization

Authorization decisions consider three elements:
- **Who** (AuthContext): The identity making the request (user or machine)
- **What** (Permission): The action being requested
- **On What** (ResourceContext): The context of the resource being accessed

## Terminology Clarification

It's important to understand the distinction between two key concepts in the authorization system:

### AuthContext vs ResourceContext

- **AuthContext**: Represents the **identity** (the "who")
  - Contains information about the user or machine making the request
  - For users: unique ID, groups, units
  - For machines: service principal ID, client ID, roles
  - Implemented by `UserAuthContext` and `MachineAuthContext` structs
  - Created during authentication, before authorization

- **ResourceContext**: Represents the **resource** (the "on what")
  - Contains key-value pairs about the resource being accessed
  - Examples: appID, unitID, environment, ownership information
  - A map type (map[string]string)
  - Enhanced by ResourceEnhancers that extract and add information

These are separate concepts used together during authorization decisions.

### ResourceEnhancers

ResourceEnhancers specifically work with ResourceContext, not AuthContext. They:
- Extract information about resources from requests
- Enrich the ResourceContext with additional data
- Do not modify the AuthContext, which is established during authentication

## How the System Works

### Core Flow

1. **Authentication** (handled by external authentication middleware): Validates tokens and extracts claims
2. **AuthContext Creation**: Application creates AuthContext from token claims
3. **ResourceContext Enhancement**: Middleware extracts and enriches resource information from the request
4. **Policy Evaluation**: Evaluator checks if the AuthContext has permission for the ResourceContext
5. **Decision Enforcement**: Middleware allows/denies the request based on the decision

### Module vs Application Responsibilities

#### What the Module Provides

**Core Components**
- [`Authorizer`](authorizer.go): Main authorization interface and implementation
- [`PolicyEvaluator`](evaluator.go): Decision engine for authorization rules
- [`Config`](config.go): Configuration structures and defaults
- [`AuthorizationService`](service.go): High-level authorization service
- [`Middleware`](middleware.go): Ready-to-use Gin middleware functions
- [`ResourceEnhancer`](enhancer.go): Unified interface for resource context extraction and enrichment

**Built-in Features**
- User/Machine context differentiation
- Role-based permission checking
- Generic resource enhancement with caching and chaining
- Comprehensive logging
- Default configuration for common scenarios

**Extension Points**
- [`ResourceEnhancer`](enhancer.go) interface for custom resource context extraction and enrichment
- Configurable role/permission mappings
- Composable enhancer chains

#### What the Application Must Provide

**Required Components**

* **Authentication Context Creation**
   ```go
   // Example: Convert authentication claims to AuthContext
   // The claims structure depends on your authentication system (OAuth2, JWT, etc.)
   type TokenClaims struct {
       ObjectID        string   `json:"oid"`        // Object ID for service principals
       AuthorizedParty string   `json:"azp"`        // Client ID
       Roles          []string `json:"roles"`       // M2M roles
       UniqueID       string   `json:"unique_id"`   // User unique identifier
       Groups         []string `json:"groups"`      // User groups
       Units          []string `json:"units"`       // User units (application-specific)
   }
   
   func CreateAuthContext(claims *TokenClaims) authorization.AuthContext {
       // Determine if this is a machine token (service principal)
       // by checking for specific fields or token type
       if claims.ObjectID != "" && len(claims.Roles) > 0 {
           return &authorization.MachineAuthContext{
               ServicePrincipalID: claims.ObjectID,
               ClientID:          claims.AuthorizedParty,
               Roles:            claims.Roles,
           }
       }
       return &authorization.UserAuthContext{
           UniqueID: claims.UniqueID,
           Groups:   claims.Groups,
           Units:    claims.Units, // Application-specific
       }
   }
   ```

* **ResourceEnhancers**

Although the module provides generic ResourceEnhancers, application-specific enhancers have to be defined in the application to keep the authorization module free of dependencies. The application should decide which enhancers to use based on their context/rules.
(an example of such definition can be found in github.com/epfl-si/md-app-portal-api/internal/api/auth/)

   ```go
   // Using generic enhancers from authorization package
   import "github.com/epfl-si/go-toolbox/authorization/enhancers"
   
   // Extract app ID from URL parameter
   paramEnhancer := enhancers.NewParamEnhancer("id", "appID")
   
   // Extract from query parameters
   queryEnhancer := enhancers.NewQueryEnhancer("env", "environment")
   
   // Using application-specific enhancers
   import localenhancers "github.com/epfl-si/md-app-portal-api/internal/api/auth/enhancers"
   
   // Create application enhancer
   appEnhancer := localenhancers.NewAppEnhancer(repo, log)
   
   // Chain multiple enhancers
   chainedEnhancer := enhancers.NewChainEnhancer(
       enhancers.NewParamEnhancer("id", "appID"),
       appEnhancer,
   )
   
   // Add caching
   cachedEnhancer, _ := enhancers.NewCacheEnhancer(chainedEnhancer, 5*time.Minute)
   ```

* **Configuration**

In the configuration each application map roles/groups/rights

   ```go
   // Create authorization configuration
   config := &authorization.Config{
       GroupMappings: map[string][]string{
           "APP-PORTAL-ADMINS": {
               "admin",
               "unit.admin",
           },
           "APP-PORTAL-READONLY": {
               "admin.readonly",
               "app.reader",
           },
           "APP-PORTAL-USERS": {
               "app.creator",
           },
       },
       RolePermissions: map[string][]authorization.Permission{
           "admin": {
               {Resource: "app", Action: "read"},
               {Resource: "app", Action: "write"},
               {Resource: "app", Action: "delete"},
               {Resource: "app", Action: "manage"},
               {Resource: "unit", Action: "read"},
               {Resource: "unit", Action: "write"},
               {Resource: "system", Action: "admin"},
               {Resource: "system", Action: "read"},
               {Resource: "secret", Action: "read"},
               {Resource: "secret", Action: "write"},
           },
           // ... other roles
       },
   }
   ```

#### What the Application Can Optionally Provide

**Optional Customizations**

1. **Custom ResourceEnhancer**

Custom enhancer can be used to enrich the ResourceContext according to the application business logic/source of information. These should be implemented in the application layer, not in the authorization module.

   ```go
   // In internal/api/auth/enhancers or another application-specific package
   type CustomEnhancer struct {
       appService *ApplicationService
       log        *zap.Logger
   }
   
   func (e *CustomEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
       result := resource.Clone()
       
       // Enrich with additional data
       if appID, ok := resource["appID"]; ok && appID != "" {
           app, err := e.appService.GetApp(ctx, appID)
           if err != nil {
               e.log.Warn("Failed to get app", zap.Error(err))
               return result, nil // Don't fail auth
           }
           result["unitID"] = app.UnitID
           result["environment"] = app.Environment
       }
       
       return result, nil
   }
   
   func (e *CustomEnhancer) Name() string {
       return "CustomEnhancer"
   }
   ```

This environment in the authorization ResourceContext could then be used to modify the unitID or any other information in the resource context, by another enhancer.

2. **Custom Permissions**

Common often used permission are provided by the module but you can create your own:

   ```go
   var (
       SecretRead  = authorization.Permission{Resource: "secret", Action: "read"}
       SecretWrite = authorization.Permission{Resource: "secret", Action: "write"}
   )
   ```

3. **Specialized Middleware**

It's easy to create a gin middleware that capture your authorization requirement/processing:

   ```go
   import (
       "github.com/epfl-si/md-app-portal-api/internal/application"
       "github.com/epfl-si/go-toolbox/authorization"
       "github.com/epfl-si/go-toolbox/authorization/enhancers"
       localenhancers "github.com/epfl-si/md-app-portal-api/internal/api/auth/enhancers"
   )

   func RequireAppOwnership(repo application.Repository, log *zap.Logger) gin.HandlerFunc {
       enhancer := enhancers.NewChainEnhancer(
           enhancers.NewParamEnhancer("id", "appID"),
           localenhancers.NewAppEnhancer(repo, log),
       )
       
       return authzService.RequirePermission(AppModify, enhancer)
   }
   ```

## Usage Examples

### 1. Basic Setup

```go
package main

import (
    "github.com/epfl-si/md-app-portal-api/internal/application"
    "github.com/epfl-si/go-toolbox/authorization"
    "github.com/epfl-si/go-toolbox/authorization/enhancers"
    localenhancers "github.com/epfl-si/md-app-portal-api/internal/api/auth/enhancers"
    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
)

func setupAuthorization(repo application.Repository, log *zap.Logger) *authorization.Service {
    // Create the application enhancer
    appEnhancer := localenhancers.NewAppEnhancer(repo, log)
    cachedEnhancer, _ := enhancers.NewCacheEnhancer(appEnhancer, 5*time.Minute)
    
    // Build the authorization system
    authorizer := authorization.NewAuthorizerBuilder().
        WithConfig(loadAuthConfig()).
        WithEnhancer(cachedEnhancer).
        WithLogger(log).
        Build()
    
    // Create authorization service for easy middleware creation
    return authorization.NewService(authorizer, cachedEnhancer, log)
}

// Usually defined elsewhere, in policy_definition.go for example
func loadAuthConfig() *authorization.Config {
    // Create authorization configuration
    return &authorization.Config{
        GroupMappings: map[string][]string{
            "APP-PORTAL-ADMINS": {
                "admin",
                "unit.admin",
            },
            "APP-PORTAL-READONLY": {
                "admin.readonly",
                "app.reader",
            },
            "APP-PORTAL-USERS": {
                "app.creator",
            },
        },
        RolePermissions: map[string][]authorization.Permission{
            "admin": {
                {Resource: "app", Action: "read"},
                {Resource: "app", Action: "write"},
                {Resource: "app", Action: "delete"},
                {Resource: "app", Action: "manage"},
                {Resource: "unit", Action: "read"},
                {Resource: "unit", Action: "write"},
                {Resource: "system", Action: "admin"},
                {Resource: "system", Action: "read"},
                {Resource: "secret", Action: "read"},
                {Resource: "secret", Action: "write"},
            },
            // ... other roles
        },
    }
}
```

### 2. Using Middleware in Routes with ResourceEnhancers

```go
import (
    "github.com/epfl-si/go-toolbox/authorization/enhancers"
    localenhancers "github.com/epfl-si/md-app-portal-api/internal/api/auth/enhancers"
)

func setupRoutes(r *gin.Engine, authz *authorization.Service, repo application.Repository, log *zap.Logger) {
    api := r.Group("/api/v1")
    
    // Require authentication for all routes
    api.Use(authenticationMiddleware)
    
    // Public endpoints - only require read permission
    api.GET("/applications", 
        authorization.RequirePermission(AppRead, nil, authz.GetAuthorizer(), log),
        listApplications)
    
    // Application-specific endpoints with resource enhancement
    appEnhancer := enhancers.NewChainEnhancer(
        enhancers.NewParamEnhancer("id", "appID"),
        localenhancers.NewAppEnhancer(repo, log),
    )
    
    // Add caching for performance
    cachedAppEnhancer, _ := enhancers.NewCacheEnhancer(appEnhancer, 5*time.Minute)
    
    api.GET("/applications/:id",
        authorization.RequirePermission(AppRead, cachedAppEnhancer, authz.GetAuthorizer(), log),
        getApplication)
    
    api.PUT("/applications/:id",
        authorization.RequirePermission(AppModify, cachedAppEnhancer, authz.GetAuthorizer(), log),
        updateApplication)
    
    api.DELETE("/applications/:id",
        authorization.RequirePermission(AppDelete, cachedAppEnhancer, authz.GetAuthorizer(), log),
        deleteApplication)
    
    // Admin-only endpoints
    admin := api.Group("/admin")
    admin.Use(authz.RequireRole("admin"))
    admin.GET("/users", listUsers)
    admin.POST("/config", updateConfig)
    
    // Multiple permission options
    api.GET("/reports",
        authorization.RequireAnyPermission([]authorization.Permission{
            {Resource: "report", Action: "read"},
            {Resource: "system", Action: "admin"},
        }, nil, authz.GetAuthorizer(), log),
        getReports)
}
```

### 3. Creating and Composing ResourceEnhancers

```go
import (
    "github.com/epfl-si/go-toolbox/authorization"
    "github.com/epfl-si/go-toolbox/authorization/enhancers"
    localenhancers "github.com/epfl-si/md-app-portal-api/internal/api/auth/enhancers"
)

// Simple parameter extraction
func createSimpleEnhancer() authorization.ResourceEnhancer {
    return enhancers.NewParamEnhancer("id", "appID")
}

// Extract from multiple sources
func createMultiSourceEnhancer() authorization.ResourceEnhancer {
    return enhancers.NewChainEnhancer(
        enhancers.NewParamEnhancer("id", "appID"),
        enhancers.NewQueryEnhancer("env", "environment"),
        enhancers.NewHeaderEnhancer("X-Tenant-ID", "tenantID"),
    )
}

// Extract from request body
func createBodyEnhancer() authorization.ResourceEnhancer {
    // Look for app_id in various possible locations in JSON
    return enhancers.NewBodyEnhancer(
        []string{"app_id", "application.id", "appId"},
        "appID",
    )
}

// Complex enhancer with database enrichment and caching
func createComplexEnhancer(repo application.Repository, log *zap.Logger) authorization.ResourceEnhancer {
    // Build the chain
    chain := enhancers.NewChainEnhancer(
        // 1. Extract from HTTP request
        enhancers.NewParamEnhancer("id", "appID"),
        enhancers.NewQueryEnhancer("env", "environment"),
        
        // 2. Enrich with database data
        localenhancers.NewAppEnhancer(repo, log),
        
        // 3. Add ownership information
        localenhancers.NewOwnershipEnhancer(repo, log),
    )
    
    // Wrap with caching for performance
    cached, err := enhancers.NewCacheEnhancer(chain, 5*time.Minute)
    if err != nil {
        log.Error("Failed to create cache", zap.Error(err))
        return chain // Fallback to uncached
    }
    
    return cached
}

// Machine-specific enhancer
func createMachineEnhancer(clientToUnits map[string][]string, log *zap.Logger) authorization.ResourceEnhancer {
    return enhancers.NewMachineUnitEnhancer(clientToUnits, log)
}
```

### 4. Custom ResourceEnhancer Implementation

```go
// Custom enhancer that enriches based on business logic
// This should be placed in the application layer, not in the authorization module
type BusinessLogicEnhancer struct {
    service BusinessService
    log     *zap.Logger
}

func NewBusinessLogicEnhancer(service BusinessService, log *zap.Logger) *BusinessLogicEnhancer {
    return &BusinessLogicEnhancer{
        service: service,
        log:     log,
    }
}

func (e *BusinessLogicEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
    result := resource.Clone()
    
    // Add business-specific enrichment
    if appID, ok := resource["appID"]; ok && appID != "" {
        // Fetch additional business data
        businessData, err := e.service.GetBusinessContext(ctx, appID)
        if err != nil {
            e.log.Warn("Failed to get business context",
                zap.String("appID", appID),
                zap.Error(err))
            return result, nil // Don't fail authorization
        }
        
        // Enrich resource context
        result["businessUnit"] = businessData.Unit
        result["costCenter"] = businessData.CostCenter
        result["riskLevel"] = businessData.RiskLevel
    }
    
    return result, nil
}

func (e *BusinessLogicEnhancer) Name() string {
    return "BusinessLogicEnhancer"
}

// Use the custom enhancer
func setupCustomRoute(r *gin.Engine, authz *authorization.Service) {
    customEnhancer := NewBusinessLogicEnhancer(businessService, log)
    enhancer := enhancers.NewChainEnhancer(
        enhancers.NewParamEnhancer("id", "appID"),
        customEnhancer,
    )
    
    r.PUT("/api/v1/business/:id",
        authorization.RequirePermission(
            BusinessPermission,
            enhancer,
            authz.GetAuthorizer(),
            log,
        ),
        updateBusinessEntity,
    )
}
```

### 5. Programmatic Authorization Checks

```go
func handleComplexOperation(c *gin.Context, authz *authorization.Service) {
    // Create enhancer for this specific check
    enhancer := enhancers.NewChainEnhancer(
        enhancers.NewParamEnhancer("id", "appID"),
        localenhancers.NewAppEnhancer(repo, log),
    )
    
    // Create context with gin context
    ctx := authorization.WithGinContext(c.Request.Context(), c)
    
    // Get auth context (from authentication)
    authCtx, err := authorization.GetAuthContext(c)
    if err != nil {
        c.JSON(401, gin.H{"error": "unauthorized"})
        return
    }
    
    // Enhance resource context
    resourceCtx := make(authorization.ResourceContext)
    resourceCtx, err = enhancer.Enhance(ctx, resourceCtx)
    if err != nil {
        c.JSON(400, gin.H{"error": "invalid request"})
        return
    }
    
    // Check permission programmatically using both contexts
    authorized, err := authz.CheckPermission(
        c.Request.Context(),
        authCtx,
        AppRead,
        resourceCtx,
    )
    
    if err != nil {
        c.JSON(500, gin.H{"error": "authorization check failed"})
        return
    }
    
    if !authorized {
        c.JSON(403, gin.H{"error": "insufficient permissions"})
        return
    }
    
    // Check role
    isAdmin := authz.GetAuthorizer().HasRole(authCtx, "admin")
    
    // Perform operation based on permissions
    if isAdmin {
        // Admin-specific logic
    } else {
        // Regular user logic
    }
}
```

### 6. ResourceEnhancers

ResourceEnhancers are a powerful unified interface that combines extraction and enrichment of resource context data. They implement the [`ResourceEnhancer`](enhancer.go) interface and can be used to:
- Extract data from HTTP requests (parameters, query, body, headers)
- Enrich ResourceContext with additional information (database lookups)
- Add computed attributes to resources
- Cache expensive operations
- Validate and transform resource data

#### Package Structure

To maintain clean dependencies, enhancers are now split into two locations:

1. **Generic enhancers** in `internal/authorization/enhancers`: These have no dependencies on other internal packages
   - HTTP enhancers (param, query, body, header)
   - Chain enhancer
   - Cache enhancer
   - Machine enhancers

2. **Application-specific enhancers** in `internal/api/auth/enhancers`: These depend on other internal packages
   - App enhancer (previously ApplicationEnhancer)
   - Config enhancer
   - Unit enhancer
   - Ownership enhancer

#### Purpose and Benefits

Enhancers unify extraction and enrichment into a single composable pattern:
- **Simplicity**: Single interface instead of separate extraction and resolution
- **Composability**: Chain multiple enhancers together easily
- **Reusability**: Share enhancers across different authorization checks
- **Performance**: Built-in caching support
- **Testability**: Clean interface with isolated components
- **Independence**: Core authorization package has no dependencies on other internal modules

#### Built-in Generic Enhancers

The authorization module provides several built-in enhancers in the `enhancers` package:

1. **HTTP Enhancers** - Extract data from HTTP requests:
   ```go
   // Extract from URL parameters
   paramEnhancer := enhancers.NewParamEnhancer("id", "appID")
   
   // Extract from query string
   queryEnhancer := enhancers.NewQueryEnhancer("env", "environment")
   
   // Extract from request body
   bodyEnhancer := enhancers.NewBodyEnhancer(
       []string{"app_id", "application.id"}, // Multiple possible paths
       "appID", // Target key in ResourceContext
   )
   
   // Extract from headers
   headerEnhancer := enhancers.NewHeaderEnhancer("X-Tenant-ID", "tenantID")
   
   // Extract multiple parameters at once
   multiEnhancer := enhancers.NewMultiParamEnhancer(map[string]string{
       "id": "appID",
       "version": "appVersion",
   })
   ```

2. **ChainEnhancer** - Compose multiple enhancers:
   ```go
   import localenhancers "github.com/epfl-si/md-app-portal-api/internal/api/auth/enhancers"

   chain := enhancers.NewChainEnhancer(
       enhancers.NewParamEnhancer("id", "appID"),
       localenhancers.NewAppEnhancer(repo, log),
       localenhancers.NewOwnershipEnhancer(repo, log),
   )
   ```

3. **CacheEnhancer** - Add caching to any enhancer:
   ```go
   cached, err := enhancers.NewCacheEnhancer(
       baseEnhancer,
       5*time.Minute, // TTL
   )
   ```

4. **Machine Enhancers** - Handle machine-to-machine contexts:
   ```go
   // Static machine unit mapping
   machineEnhancer := enhancers.NewMachineUnitEnhancer(
       map[string][]string{
           "client-123": {"unit-456", "unit-789"},
       },
       log,
   )
   
   // Dynamic machine unit resolution
   dynamicEnhancer := enhancers.NewDynamicMachineUnitEnhancer(
       func(ctx context.Context, clientID string) ([]string, error) {
           return fetchUnitsForClient(clientID)
       },
       log,
   )
   ```

#### Application-Specific Enhancers

These enhancers are located in `internal/api/auth/enhancers` since they depend on the application repository:

```go
import (
    "github.com/epfl-si/md-app-portal-api/internal/application"
    localenhancers "github.com/epfl-si/md-app-portal-api/internal/api/auth/enhancers"
)

// Enrich with application data
appEnhancer := localenhancers.NewAppEnhancer(repo, log)

// Enrich with config data
configEnhancer := localenhancers.NewConfigEnhancer(repo, log)

// Add ownership information
ownershipEnhancer := localenhancers.NewOwnershipEnhancer(repo, log)
```

#### Creating a Custom Enhancer

Implement the [`ResourceEnhancer`](enhancer.go) interface:

```go
type ResourceEnhancer interface {
    Enhance(ctx context.Context, resource ResourceContext) (ResourceContext, error)
    Name() string
}
```

**Example: Tenant-Aware Enhancer**

```go
// Place this in the application layer
type TenantEnhancer struct {
    tenantService TenantService
    log          *zap.Logger
}

func NewTenantEnhancer(service TenantService, log *zap.Logger) *TenantEnhancer {
    return &TenantEnhancer{
        tenantService: service,
        log:          log,
    }
}

func (e *TenantEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
    result := resource.Clone()
    
    // Extract tenant from gin context if available
    if ginCtx, ok := authorization.GetGinContext(ctx); ok {
        tenantID := ginCtx.GetHeader("X-Tenant-ID")
        if tenantID == "" {
            tenantID = ginCtx.Query("tenant")
        }
        
        if tenantID != "" {
            // Validate and enrich tenant information
            tenant, err := e.tenantService.GetTenant(ctx, tenantID)
            if err != nil {
                e.log.Warn("Invalid tenant", zap.String("tenantID", tenantID))
                return result, nil
            }
            
            result["tenantID"] = tenant.ID
            result["tenantPlan"] = tenant.Plan
            result["tenantLimits"] = tenant.Limits
        }
    }
    
    return result, nil
}

func (e *TenantEnhancer) Name() string {
    return "TenantEnhancer"
}
```

#### Enhancer Best Practices

1. **Always clone the ResourceContext** before modifying:
   ```go
   result := resource.Clone()
   ```

2. **Handle errors gracefully** - don't fail authorization for missing data:
   ```go
   if err != nil {
       log.Warn("Failed to enhance", zap.Error(err))
       return result, nil // Return what we have
   }
   ```

3. **Check for existing data** to avoid unnecessary work:
   ```go
   if _, exists := resource["unitID"]; exists {
       return result, nil
   }
   ```

4. **Use caching** for expensive operations:
   ```go
   cached, _ := enhancers.NewCacheEnhancer(enhancer, 5*time.Minute)
   ```

5. **Keep enhancers focused** - each should do one thing well

6. **Use descriptive names** for debugging:
   ```go
   func (e *MyEnhancer) Name() string {
       return "MyEnhancer[specific-purpose]"
   }
   ```

7. **Place application-specific enhancers** in the application layer, not in the authorization module

8. **Compose enhancers** for complex scenarios:
   ```go
   chain := enhancers.NewChainEnhancer(
       extractEnhancer,  // Extract from request
       validateEnhancer, // Validate data
       enrichEnhancer,   // Enrich with DB data
       cacheEnhancer,    // Cache the result
   )
   ```

## Unit-Scoped Access

Unit-scoped access is an important security feature that ensures users and services can only access resources belonging to their authorized organizational units. This creates effective isolation boundaries between different departments or teams.

### How Unit-Scoped Access Works

#### Definition and Resolution

1. **Unit Definition**
   - **For Users**: Units are explicitly defined in the `UserAuthContext` and come directly from authentication tokens
   - **For M2M (Services)**: Units are resolved dynamically through a `ResourceEnhancer` that populates a `machineUnits` field in the `ResourceContext`

2. **Permission Evaluation Process**
   - The system first checks if a resource has a `unitID` field in the `ResourceContext`
   - If present, this triggers unit-scoped permission evaluation with the following priority:
     1. Check if the user/machine has access to the specific unit
     2. If yes, check if their roles grant unit-scoped permissions
     3. If no, deny access **even if they have global permissions**

3. **Unit-Scoped vs. Global Permissions**
   - Unit-scoped permissions are defined separately from global permissions
   - They allow for more fine-grained control, where users might have certain capabilities only within their units
   - **Critical Security Feature**: Global permissions cannot bypass unit scoping

### M2M Unit Resolution

For machine-to-machine authentication, unit resolution works differently than for users:

1. **Resource Enhancer Mechanism**
   - Since M2M tokens don't inherently contain unit information, a `ResourceEnhancer` dynamically resolves units
   - The enhancer adds a comma-separated `machineUnits` field to the `ResourceContext`
   - The system then checks if the resource's unit is in this list

2. **Implementation Options**
   - **Static Mapping**: Use `NewMachineUnitEnhancer` with a predefined mapping of client IDs to units
   ```go
   machineEnhancer := enhancers.NewMachineUnitEnhancer(
       map[string][]string{
           "client-123": {"unit-456", "unit-789"},
       },
       log,
   )
   ```
   
   - **Dynamic Resolution**: Use `NewDynamicMachineUnitEnhancer` with a function that looks up units
   ```go
   dynamicEnhancer := enhancers.NewDynamicMachineUnitEnhancer(
       func(ctx context.Context, clientID string) ([]string, error) {
           return fetchUnitsForClient(clientID)
       },
       log,
   )
   ```

3. **Unit-Scoped M2M Authorization Flow**
   - M2M client makes request with its token
   - System extracts client ID from token
   - Resource enhancer resolves authorized units for this client
   - System checks if resource's unitID is in the authorized units
   - If matching, checks if the client's roles grant unit-scoped permissions

### Defining Unit-Scoped Permissions

Unit-scoped permissions are defined in the `unitScopedRoles` section of the configuration:

```json
{
  "unitScopedRoles": {
    "unit.admin": [
      {"resource": "app", "action": "read"},
      {"resource": "app", "action": "write"},
      {"resource": "app", "action": "delete"},
      {"resource": "app", "action": "manage"},
      {"resource": "secret", "action": "read"},
      {"resource": "secret", "action": "write"}
    ],
    "app.creator": [
      {"resource": "app", "action": "read"},
      {"resource": "app", "action": "write"},
      {"resource": "secret", "action": "write"}
    ],
    "service.principal": [
      {"resource": "app", "action": "read"}
    ]
  }
}
```

The configuration is loaded into the `Config` struct:

```go
type Config struct {
    RolePermissions map[string][]Permission // Maps roles to the permissions they grant
    GroupMappings   map[string][]string     // Maps AD groups to internal roles
    MachineUnits    map[string][]string     // Maps client IDs to allowed unit IDs
    UnitScopedRoles map[string][]Permission // Maps roles to unit-scoped permissions
}
```

And the permissions are checked using the `HasUnitScopedPermission` method:

```go
func (c *Config) HasUnitScopedPermission(role string, permission Permission) bool {
    permissions, exists := c.UnitScopedRoles[role]
    if !exists {
        return false
    }

    for _, p := range permissions {
        if p.Equals(permission) {
            return true
        }
    }
    return false
}
```

Key points about unit-scoped permission definition:

1. **Separate Definition**: Unit-scoped permissions are defined separately from global permissions
2. **Role-Based Structure**: They're organized by role, with each role having a list of allowed unit-scoped permissions
3. **Runtime Configuration**: Unit-scoped permissions can be modified without code changes
4. **Customization**: To customize unit-scoped permissions, update the configuration file
5. **Backward Compatibility**: Default values are provided if the configuration is missing

### Security Considerations

- Unit-scoped access is a critical security boundary that prevents privilege escalation
- Even users/services with global permissions cannot access resources in units they don't belong to
- This creates effective isolation between different organizational units
- The system enforces unit scope checks before checking global permissions

### 7. Testing Authorization

```go
import (
    "github.com/epfl-si/go-toolbox/authorization"
    "github.com/epfl-si/go-toolbox/authorization/enhancers"
    localenhancers "github.com/epfl-si/md-app-portal-api/internal/api/auth/enhancers"
)

func TestApplicationAuthorization(t *testing.T) {
    // Create mock auth context (identity)
    userCtx := &authorization.UserAuthContext{
        UniqueID: "user-123",
        Groups:   []string{"APP-CREATORS"},
        Units:    []string{"unit-456"},
    }
    
    // Create test configuration
    config := &authorization.Config{
        GroupMappings: map[string][]string{
            "APP-CREATORS": {"app.creator"},
        },
        RolePermissions: map[string][]authorization.Permission{
            "app.creator": {
                {Resource: "app", Action: "write"},
            },
        },
    }
    
    // Create evaluator
    evaluator := authorization.NewPolicyEvaluator(config, nil)
    
    // Test authorization with a
