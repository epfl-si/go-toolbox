# Authorization Package

This package provides a flexible authorization system for Go applications, with support for role-based access control, unit-scoped permissions, and machine-to-machine authorization.

## Authorization Flow

The authorization system uses a two-tier evaluation model:

### Tier 1: Global Role Bypass
- Checks if user has a global role with required permission
- If found, grants access immediately (bypasses unit checks)
- Example: `admin` role has global `unit:write` permission

### Tier 2: Unit-Scoped Permissions
- Only evaluated if Tier 1 fails
- Requires BOTH conditions:
  1. User has role with unit-scoped permission
  2. Target unit is in user's accessible units list
- Example: `unit.admin` role has `unit:write` for their assigned units only

### Example

User with roles `["admin", "unit.admin"]` and units `["16000"]`:
- Accessing unit "16000": GRANTED (via Tier 1 global bypass)
- Accessing unit "99999": GRANTED (via Tier 1 global bypass)

User with roles `["unit.admin"]` and units `["16000"]`:
- Accessing unit "16000": GRANTED (via Tier 2 unit-scoped)
- Accessing unit "99999": DENIED (not in accessible units)

## Components

### AuthContext
Represents the authentication context of a user or machine, including:
- Unique identifier
- Roles
- Groups
- Units

### Permission
Represents a required permission with resource and action:
```go
type Permission struct {
    Resource string // "app", "unit", "secret", "system", etc.
    Action   string // "read", "write", "delete", "admin"
}
```

### ResourceContext
Contains information about the resource being accessed, such as:
```go
ResourceContext{
    "unitID": "16000",
    "machineUnits": "16000,16001,16002",
}
```

### PolicyEvaluator
Makes the actual authorization decisions based on:
1. AuthContext (who is requesting)
2. Permission (what they want to do)
3. ResourceContext (what they want to access)

## Usage

```go
// Create an evaluator with configuration
config := &authorization.Config{
    RolePermissions: map[string][]authorization.Permission{
        "admin": {
            {Resource: "unit", Action: "write"},
        },
    },
    UnitScopedRoles: map[string][]authorization.Permission{
        "unit.admin": {
            {Resource: "unit", Action: "write"},
        },
    },
}
evaluator := authorization.NewPolicyEvaluator(config, logger)

// Evaluate a permission
authCtx := &authorization.UserAuthContext{
    UniqueID: "user-1",
    Groups:   []string{"ADMINS"},
    Units:    []string{"16000"},
}
permission := authorization.Permission{Resource: "unit", Action: "write"}
resourceContext := authorization.ResourceContext{"unitID": "99999"}

authorized, reason := evaluator.Evaluate(authCtx, permission, resourceContext)
```

## Configuration

The authorization system is configured using a `Config` struct:

```go
type Config struct {
    RolePermissions map[string][]Permission // Maps roles to the permissions they grant
    GroupMappings   map[string][]string     // Maps AD groups to internal roles
    MachineUnits    map[string][]string     // Maps client IDs to allowed unit IDs
    UnitScopedRoles map[string][]Permission // Maps roles to unit-scoped permissions
}
```

## Machine-to-Machine Authorization

For machine-to-machine authorization, the system supports:
1. Global permissions via roles
2. Unit-scoped permissions with machine unit associations
