package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestM2MUnitScopedPermissions_WithoutAllowedUnits tests that M2M tokens without
// AllowedUnits are denied when they don't have global permissions for the action
func TestM2MUnitScopedPermissions_WithoutAllowedUnits(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-PORTAL-USERS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "unit", Action: "read"},
				// NOTE: 'app:write' is NOT in global permissions
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
		// No AllowedUnits
	}

	permission := Permission{Resource: "app", Action: "write"}
	resourceContext := ResourceContext{"unitID": "unit-123"}

	evaluator := NewPolicyEvaluator(config, nil)
	authorized, reason := evaluator.Evaluate(m2mContext, permission, resourceContext)
	assert.Equal(t, "machine_no_units_configured", reason, "Machine without AllowedUnits should get no_units_configured")
	assert.False(t, authorized, "Expected authorization to be denied without AllowedUnits, but was granted. Reason: %s", reason)
}

// TestM2MUnitScopedPermissions_WithAllowedUnits tests M2M with AllowedUnits on AuthContext
func TestM2MUnitScopedPermissions_WithAllowedUnits(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "unit", Action: "read"},
				// NOTE: 'app:write' is NOT in global permissions
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

	// M2M context with AllowedUnits set directly
	m2mContext := &MachineAuthContext{
		ServicePrincipalID: "test-sp-id",
		ClientID:           "test-client-id",
		Roles:              []string{"app.creator"},
		AllowedUnits:       []string{"unit-123", "unit-456"},
	}

	permission := Permission{Resource: "app", Action: "write"}
	evaluator := NewPolicyEvaluator(config, nil)

	// Test 1: Access to unit-123 (authorized — unit matches)
	authorized1, reason1 := evaluator.Evaluate(m2mContext, permission, ResourceContext{"unitID": "unit-123"})
	assert.Equal(t, "machine_unit_match_app.creator", reason1, "Machine with matching unit should be authorized")
	assert.True(t, authorized1, "Expected authorization for unit-123, but was denied. Reason: %s", reason1)

	// Test 2: Access to unit-999 (not authorized — unit mismatch)
	authorized2, reason2 := evaluator.Evaluate(m2mContext, permission, ResourceContext{"unitID": "unit-999"})
	assert.Equal(t, "machine_unit_mismatch_required_unit-999", reason2, "Machine with non-matching unit should NOT be authorized")
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
				// NOTE: 'app:write' is NOT in global permissions
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
	userAuthorized, userReason := evaluator.Evaluate(userContext, permission, ResourceContext{"unitID": "unit-123"})
	assert.Equal(t, "user_unit_match_app.creator", userReason, "User with matching unit should be authorized")

	// Test M2M with AllowedUnits directly on context
	m2mContext := &MachineAuthContext{
		ServicePrincipalID: "test-sp-id",
		ClientID:           "test-client-id",
		Roles:              []string{"app.creator"},
		AllowedUnits:       []string{"unit-123"},
	}

	m2mAuthorized, m2mReason := evaluator.Evaluate(m2mContext, permission, ResourceContext{"unitID": "unit-123"})
	assert.Equal(t, "machine_unit_match_app.creator", m2mReason, "Machine with matching unit should be authorized")
	assert.True(t, userAuthorized, "Expected user authorization to be granted. Reason: %s", userReason)
	assert.True(t, m2mAuthorized, "Expected M2M authorization to be granted. Reason: %s", m2mReason)

	// Results should match
	assert.Equal(t, userAuthorized, m2mAuthorized, "Authorization inconsistency: user=%v, m2m=%v", userAuthorized, m2mAuthorized)
}

// TestGlobalPermissionBypassesUnitScoping verifies that global permissions bypass unit scoping
func TestGlobalPermissionBypassesUnitScoping(t *testing.T) {
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

	// User has global admin role with app:write but tries to access unit-scoped resource
	// The user does NOT belong to unit-456, but should still get access due to global role bypass
	userContext := &UserAuthContext{
		UniqueID: "test-admin-user",
		Groups:   []string{"APP-PORTAL-ADMINS"},
		Units:    []string{"unit-123"}, // User only has access to unit-123
	}

	resourceContext := ResourceContext{"unitID": "unit-456"}
	authorized, reason := evaluator.Evaluate(userContext, permission, resourceContext)

	assert.True(t, authorized, "User with global permission should bypass unit scoping. Reason: %s", reason)
	assert.Equal(t, "user_global_role_bypass_admin", reason, "Expected global role bypass")
}
