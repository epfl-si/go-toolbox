package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// 2.1 UserAuthContext Tests
// ============================================================================

func TestUserAuthContext_GetIdentifier(t *testing.T) {
	userCtx := &UserAuthContext{
		UniqueID: "user-12345",
		ClientID: "client-abc",
	}

	got := userCtx.GetIdentifier()
	assert.Equal(t, "user-12345", got)
}

func TestUserAuthContext_GetClientID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
	}{
		{
			name:     "with client ID",
			clientID: "client-123",
		},
		{
			name:     "empty client ID",
			clientID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx := &UserAuthContext{
				ClientID: tt.clientID,
			}
			got := userCtx.GetClientID()
			assert.Equal(t, tt.clientID, got)
		})
	}
}

func TestUserAuthContext_TypeChecks(t *testing.T) {
	userCtx := &UserAuthContext{
		UniqueID: "user-123",
	}

	assert.True(t, userCtx.IsUser(), "UserAuthContext should return true for IsUser()")
	assert.False(t, userCtx.IsMachine(), "UserAuthContext should return false for IsMachine()")
}

func TestUserAuthContext_GetGroups(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
	}{
		{
			name:   "single group",
			groups: []string{"APP-ADMINS"},
		},
		{
			name:   "multiple groups",
			groups: []string{"APP-ADMINS", "APP-READERS", "DEPT-A"},
		},
		{
			name:   "no groups",
			groups: []string{},
		},
		{
			name:   "nil groups",
			groups: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx := &UserAuthContext{
				Groups: tt.groups,
			}
			got := userCtx.GetGroups()
			assert.Equal(t, tt.groups, got)
		})
	}
}

func TestUserAuthContext_GetUnits(t *testing.T) {
	tests := []struct {
		name  string
		units []string
	}{
		{
			name:  "single unit",
			units: []string{"unit-123"},
		},
		{
			name:  "multiple units",
			units: []string{"unit-123", "unit-456", "unit-789"},
		},
		{
			name:  "no units",
			units: []string{},
		},
		{
			name:  "nil units",
			units: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx := &UserAuthContext{
				Units: tt.units,
			}
			got := userCtx.GetUnits()
			assert.Equal(t, tt.units, got)
		})
	}
}

func TestUserAuthContext_GetRoles(t *testing.T) {
	tests := []struct {
		name  string
		roles []string
	}{
		{
			name:  "single role",
			roles: []string{"admin"},
		},
		{
			name:  "multiple roles",
			roles: []string{"admin", "readonly", "app.creator"},
		},
		{
			name:  "no roles",
			roles: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx := &UserAuthContext{
				Roles: tt.roles,
			}
			got := userCtx.GetRoles()
			assert.Equal(t, tt.roles, got)
		})
	}
}

// ============================================================================
// 2.2 MachineAuthContext Tests
// ============================================================================

func TestMachineAuthContext_GetIdentifier(t *testing.T) {
	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-12345",
		ClientID:           "client-abc",
	}

	got := machineCtx.GetIdentifier()
	assert.Equal(t, "sp-12345", got)
}

func TestMachineAuthContext_GetClientID(t *testing.T) {
	machineCtx := &MachineAuthContext{
		ClientID: "client-123",
	}

	got := machineCtx.GetClientID()
	assert.Equal(t, "client-123", got)
}

func TestMachineAuthContext_TypeChecks(t *testing.T) {
	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
	}

	assert.False(t, machineCtx.IsUser(), "MachineAuthContext should return false for IsUser()")
	assert.True(t, machineCtx.IsMachine(), "MachineAuthContext should return true for IsMachine()")
}

func TestMachineAuthContext_GetUnits(t *testing.T) {
	// Machines should always return empty units
	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
	}

	got := machineCtx.GetUnits()
	assert.Empty(t, got, "MachineAuthContext should always return empty units")
	assert.NotNil(t, got, "MachineAuthContext should return non-nil slice")
}

func TestMachineAuthContext_GetRoles(t *testing.T) {
	tests := []struct {
		name  string
		roles []string
	}{
		{
			name:  "single role",
			roles: []string{"service.principal"},
		},
		{
			name:  "multiple roles",
			roles: []string{"service.principal", "app.creator"},
		},
		{
			name:  "no roles",
			roles: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machineCtx := &MachineAuthContext{
				Roles: tt.roles,
			}
			got := machineCtx.GetRoles()
			assert.Equal(t, tt.roles, got)
		})
	}
}

func TestMachineAuthContext_GetGroups(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
	}{
		{
			name:   "single app role",
			groups: []string{"AppRole1"},
		},
		{
			name:   "multiple app roles",
			groups: []string{"AppRole1", "AppRole2"},
		},
		{
			name:   "no groups",
			groups: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machineCtx := &MachineAuthContext{
				Groups: tt.groups,
			}
			got := machineCtx.GetGroups()
			assert.Equal(t, tt.groups, got)
		})
	}
}

// ============================================================================
// 2.3 ResourceContext Tests
// ============================================================================

func TestResourceContext_GetSetHas(t *testing.T) {
	rc := ResourceContext{}

	// Test Set and Get
	rc.Set("appID", "app-123")
	rc.Set("unitID", "unit-456")

	assert.Equal(t, "app-123", rc.Get("appID"))
	assert.Equal(t, "unit-456", rc.Get("unitID"))

	// Test Has
	assert.True(t, rc.Has("appID"))
	assert.True(t, rc.Has("unitID"))
	assert.False(t, rc.Has("nonexistent"))

	// Test Get on non-existent key returns empty string
	assert.Equal(t, "", rc.Get("nonexistent"))
}

func TestResourceContext_Clone(t *testing.T) {
	original := ResourceContext{
		"appID":  "app-123",
		"unitID": "unit-456",
		"env":    "prod",
	}

	clone := original.Clone()

	// Verify clone has same data
	assert.Equal(t, "app-123", clone.Get("appID"))
	assert.Equal(t, "unit-456", clone.Get("unitID"))
	assert.Equal(t, "prod", clone.Get("env"))

	// Verify original and clone are independent
	clone.Set("appID", "app-999")
	clone.Set("new", "value")

	assert.Equal(t, "app-123", original.Get("appID"), "Original should not be affected by clone changes")
	assert.False(t, original.Has("new"), "Original should not have keys added to clone")
	assert.Equal(t, "app-999", clone.Get("appID"), "Clone should have new value")
	assert.True(t, clone.Has("new"), "Clone should have new key")
}

func TestResourceContext_MapBehavior(t *testing.T) {
	// Test direct map operations
	rc := ResourceContext{
		"key1": "value1",
		"key2": "value2",
	}

	// Test that it works as a map
	assert.Equal(t, "value1", rc["key1"])
	assert.Equal(t, "value2", rc["key2"])

	// Test modification
	rc["key3"] = "value3"
	assert.True(t, rc.Has("key3"))
	assert.Equal(t, "value3", rc.Get("key3"))

	// Test deletion
	delete(rc, "key1")
	assert.False(t, rc.Has("key1"))
}

// ============================================================================
// 2.4 Context Storage Tests
// ============================================================================

func TestContext_WithAuthContext_GetAuthContextFromCtx(t *testing.T) {
	tests := []struct {
		name    string
		authCtx AuthContext
	}{
		{
			name: "user context",
			authCtx: &UserAuthContext{
				UniqueID: "user-123",
				Groups:   []string{"ADMINS"},
				Units:    []string{"unit-1"},
			},
		},
		{
			name: "machine context",
			authCtx: &MachineAuthContext{
				ServicePrincipalID: "sp-456",
				ClientID:           "client-789",
				Roles:              []string{"service.principal"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Store auth context
			ctx = WithAuthContext(ctx, tt.authCtx)

			// Retrieve auth context
			retrieved, ok := GetAuthContextFromCtx(ctx)
			assert.True(t, ok, "Should successfully retrieve auth context")
			assert.Equal(t, tt.authCtx, retrieved)
		})
	}
}

func TestContext_GetAuthContextFromCtx_NotFound(t *testing.T) {
	ctx := context.Background()

	// Try to retrieve from empty context
	retrieved, ok := GetAuthContextFromCtx(ctx)
	assert.False(t, ok, "Should return false when auth context not found")
	assert.Nil(t, retrieved, "Should return nil when auth context not found")
}

func TestContext_WithResourceContext_GetResourceContextFromCtx(t *testing.T) {
	tests := []struct {
		name        string
		resourceCtx ResourceContext
	}{
		{
			name: "simple resource context",
			resourceCtx: ResourceContext{
				"appID": "app-123",
			},
		},
		{
			name: "complex resource context",
			resourceCtx: ResourceContext{
				"appID":        "app-456",
				"unitID":       "unit-789",
				"environment":  "production",
				"machineUnits": "unit-1,unit-2,unit-3",
			},
		},
		{
			name:        "empty resource context",
			resourceCtx: ResourceContext{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Store resource context
			ctx = WithResourceContext(ctx, tt.resourceCtx)

			// Retrieve resource context
			retrieved, ok := GetResourceContextFromCtx(ctx)
			assert.True(t, ok, "Should successfully retrieve resource context")
			assert.Equal(t, tt.resourceCtx, retrieved)
		})
	}
}

func TestContext_GetResourceContextFromCtx_NotFound(t *testing.T) {
	ctx := context.Background()

	// Try to retrieve from empty context
	retrieved, ok := GetResourceContextFromCtx(ctx)
	assert.False(t, ok, "Should return false when resource context not found")
	assert.Nil(t, retrieved, "Should return nil when resource context not found")
}

func TestContext_MultipleContextValues(t *testing.T) {
	ctx := context.Background()

	// Store both auth and resource contexts
	authCtx := &UserAuthContext{
		UniqueID: "user-123",
		Groups:   []string{"ADMINS"},
	}
	resourceCtx := ResourceContext{
		"appID": "app-456",
	}

	ctx = WithAuthContext(ctx, authCtx)
	ctx = WithResourceContext(ctx, resourceCtx)

	// Retrieve both
	retrievedAuth, authOk := GetAuthContextFromCtx(ctx)
	retrievedResource, resourceOk := GetResourceContextFromCtx(ctx)

	assert.True(t, authOk)
	assert.True(t, resourceOk)
	assert.Equal(t, authCtx, retrievedAuth)
	assert.Equal(t, resourceCtx, retrievedResource)
}

func TestContext_OverwritingContextValues(t *testing.T) {
	ctx := context.Background()

	// Store first auth context
	authCtx1 := &UserAuthContext{
		UniqueID: "user-123",
	}
	ctx = WithAuthContext(ctx, authCtx1)

	// Overwrite with second auth context
	authCtx2 := &UserAuthContext{
		UniqueID: "user-456",
	}
	ctx = WithAuthContext(ctx, authCtx2)

	// Should retrieve the second one
	retrieved, ok := GetAuthContextFromCtx(ctx)
	assert.True(t, ok)
	assert.Equal(t, authCtx2, retrieved)
	assert.NotEqual(t, authCtx1, retrieved)
}

// ============================================================================
// Interface Compliance Tests
// ============================================================================

func TestAuthContextInterface(t *testing.T) {
	// Verify both types implement AuthContext interface
	var _ AuthContext = &UserAuthContext{}
	var _ AuthContext = &MachineAuthContext{}

	// This test ensures compilation will fail if interface is not properly implemented
}
