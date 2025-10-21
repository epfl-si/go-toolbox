package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestM2MUnitScopedPermissions_WithoutResolver tests that M2M tokens without a resolver are denied
func TestM2MUnitScopedPermissions_WithoutResolver(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-PORTAL-USERS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "unit", Action: "read"},
				// NOTE: 'app:write' is only unit-scoped, not global
			},
		},
		UnitScopedRoles: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "secret", Action: "write"},
			},
		},
	}

	m2mContext := &MachineAuthContext{
		ServicePrincipalID: "test-sp-id",
		ClientID:           "test-client-id",
		Roles:              []string{"app.creator"},
	}

	permission := Permission{Resource: "app", Action: "write"}
	resourceContext := ResourceContext{"unitID": "unit-123"}

	evaluator := NewPolicyEvaluator(config, nil)
	authorized, reason := evaluator.Evaluate(m2mContext, permission, resourceContext)
	assert.Equal(t, "machine_unit_required_unit-123", reason, "Machine without resolver shouldn't be authorized for unit-scoped resource")
	assert.False(t, authorized, "Expected authorization to be denied without resolver, but was granted. Reason: %s", reason)
}

// TestM2MUnitScopedPermissions_WithResolver tests M2M with MachineUnitResolver
func TestM2MUnitScopedPermissions_WithResolver(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "unit", Action: "read"},
				// 'app:write' is unit-scoped only
			},
		},
		UnitScopedRoles: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "secret", Action: "write"},
			},
		},
	}

	// Create M2M context
	m2mContext := &MachineAuthContext{
		ServicePrincipalID: "test-sp-id",
		ClientID:           "test-client-id",
		Roles:              []string{"app.creator"},
	}

	// Create a mock enhancer that grants units to this client
	mockEnhancer := &mockMachineUnitEnhancer{
		clientToUnits: map[string][]string{
			"test-client-id": {"unit-123", "unit-456"},
		},
	}

	permission := Permission{Resource: "app", Action: "write"}

	// Test 1: Access to unit-123 (authorized)
	resourceContext1 := ResourceContext{"unitID": "unit-123"}
	enrichedResource1, _ := mockEnhancer.Enhance(
		withAuthContext(context.Background(), m2mContext),
		resourceContext1,
	)

	evaluator := NewPolicyEvaluator(config, nil)
	authorized1, reason1 := evaluator.Evaluate(m2mContext, permission, enrichedResource1)
	assert.Equal(t, "machine_unit_match_app.creator", reason1, "Machine with resolver and matching unit should be authorized")
	assert.True(t, authorized1, "Expected authorization for unit-123, but was denied. Reason: %s", reason1)

	// Test 2: Access to unit-999 (not authorized)
	resourceContext2 := ResourceContext{"unitID": "unit-999"}
	enrichedResource2, _ := mockEnhancer.Enhance(
		withAuthContext(context.Background(), m2mContext),
		resourceContext2,
	)

	authorized2, reason2 := evaluator.Evaluate(m2mContext, permission, enrichedResource2)
	assert.Equal(t, "machine_unit_mismatch_required_unit-999", reason2, "Machine with resolver and non-matching unit should NOT be authorized")
	assert.False(t, authorized2, "Expected denial for unit-999, but was granted. Reason: %s", reason2)
}

// TestM2MUnitScopedPermissions_ConsistencyWithUser verifies M2M and User behave identically
func TestM2MUnitScopedPermissions_ConsistencyWithUser(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-PORTAL-USERS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
			},
		},
		UnitScopedRoles: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "secret", Action: "write"},
			},
		},
	}

	permission := Permission{Resource: "app", Action: "write"}
	evaluator := NewPolicyEvaluator(config, nil)

	// Test User
	userContext := &UserAuthContext{
		UniqueID: "test-user",
		Groups:   []string{"APP-PORTAL-USERS"},
		Units:    []string{"unit-123"},
	}
	userResourceContext := ResourceContext{"unitID": "unit-123"}
	userAuthorized, userReason := evaluator.Evaluate(userContext, permission, userResourceContext)
	assert.Equal(t, "user_unit_match_app.creator", userReason, "User with matching unit should be authorized")

	// Test M2M with resolver
	m2mContext := &MachineAuthContext{
		ServicePrincipalID: "test-sp-id",
		ClientID:           "test-client-id",
		Roles:              []string{"app.creator"},
	}

	mockEnhancer := &mockMachineUnitEnhancer{
		clientToUnits: map[string][]string{
			"test-client-id": {"unit-123"},
		},
	}

	m2mResourceContext := ResourceContext{"unitID": "unit-123"}
	enrichedM2MResource, _ := mockEnhancer.Enhance(
		withAuthContext(context.Background(), m2mContext),
		m2mResourceContext,
	)

	m2mAuthorized, m2mReason := evaluator.Evaluate(m2mContext, permission, enrichedM2MResource)
	assert.Equal(t, "machine_unit_match_app.creator", m2mReason, "Machine with matching unit should be authorized")
	assert.True(t, userAuthorized, "Expected user authorization to be granted. Reason: %s", userReason)
	assert.True(t, m2mAuthorized, "Expected M2M authorization to be granted. Reason: %s", m2mReason)

	// Results should match
	assert.Equal(t, userAuthorized, m2mAuthorized, "Authorization inconsistency: user=%v, m2m=%v", userAuthorized, m2mAuthorized)
}

// TestGlobalPermissionDoesNotBypassUnitScoping verifies that global permissions cannot bypass unit scoping
func TestGlobalPermissionDoesNotBypassUnitScoping(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-PORTAL-ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"}, // Global permission for app:write
			},
		},
		UnitScopedRoles: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "app", Action: "delete"},
				{Resource: "app", Action: "manage"},
				{Resource: "secret", Action: "read"},
				{Resource: "secret", Action: "write"},
			},
		},
	}

	permission := Permission{Resource: "app", Action: "write"}
	evaluator := NewPolicyEvaluator(config, nil)

	// Test: User has global admin role with app:write but tries to access unit-scoped resource
	// The user does NOT belong to unit-456, so access should be denied
	userContext := &UserAuthContext{
		UniqueID: "test-admin-user",
		Groups:   []string{"APP-PORTAL-ADMINS"},
		Units:    []string{"unit-123"}, // User only has access to unit-123
	}

	// Try to access a resource in unit-456 (user doesn't have access to this unit)
	resourceContext := ResourceContext{"unitID": "unit-456"}
	authorized, reason := evaluator.Evaluate(userContext, permission, resourceContext)

	// CRITICAL: Even though the user has global app:write permission,
	// they should be DENIED because the resource requires unit-456 access
	assert.False(t, authorized, "User with global permission should NOT bypass unit scoping. Reason: %s", reason)
	assert.Equal(t, "user_unit_mismatch_required_unit-456", reason, "Expected unit mismatch denial")
}

// mockMachineUnitEnhancer is a test helper that implements ResourceEnhancer
type mockMachineUnitEnhancer struct {
	clientToUnits map[string][]string
}

func (r *mockMachineUnitEnhancer) Enhance(ctx context.Context, resource ResourceContext) (ResourceContext, error) {
	result := resource.Clone()

	authCtx, ok := GetAuthContextFromCtx(ctx)
	if !ok || !authCtx.IsMachine() {
		return result, nil
	}

	clientID := authCtx.GetClientID()
	if units, ok := r.clientToUnits[clientID]; ok && len(units) > 0 {
		// Join units as comma-separated string
		unitsStr := units[0]
		for i := 1; i < len(units); i++ {
			unitsStr += "," + units[i]
		}
		result["machineUnits"] = unitsStr
	}

	return result, nil
}

func (r *mockMachineUnitEnhancer) Name() string {
	return "MockMachineUnitEnhancer"
}

// withAuthContext adds auth context to a Go context
func withAuthContext(ctx context.Context, authCtx AuthContext) context.Context {
	return WithAuthContext(ctx, authCtx)
}
