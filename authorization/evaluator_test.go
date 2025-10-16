package authorization

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// ============================================================================
// 4.1 System Permission Evaluation
// ============================================================================

func TestEvaluator_SystemPermission_AdminRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "system", Action: "read"},
				{Resource: "system", Action: "write"},
				{Resource: "system", Action: "admin"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	tests := []struct {
		name       string
		authCtx    AuthContext
		permission Permission
		wantAuth   bool
	}{
		{
			name: "user with admin role - system:read",
			authCtx: &UserAuthContext{
				UniqueID: "user-1",
				Groups:   []string{"ADMINS"},
			},
			permission: Permission{Resource: "system", Action: "read"},
			wantAuth:   true,
		},
		{
			name: "user with admin role - system:write",
			authCtx: &UserAuthContext{
				UniqueID: "user-1",
				Groups:   []string{"ADMINS"},
			},
			permission: Permission{Resource: "system", Action: "write"},
			wantAuth:   true,
		},
		{
			name: "user with admin role - system:admin",
			authCtx: &UserAuthContext{
				UniqueID: "user-1",
				Groups:   []string{"ADMINS"},
			},
			permission: Permission{Resource: "system", Action: "admin"},
			wantAuth:   true,
		},
		{
			name: "machine with admin role - system:admin",
			authCtx: &MachineAuthContext{
				ServicePrincipalID: "sp-1",
				Roles:              []string{"admin"},
			},
			permission: Permission{Resource: "system", Action: "admin"},
			wantAuth:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorized, reason := evaluator.Evaluate(tt.authCtx, tt.permission, ResourceContext{})
			assert.Equal(t, tt.wantAuth, authorized)
			if tt.wantAuth {
				assert.Contains(t, reason, "system_permission_via_role")
			}
		})
	}
}

func TestEvaluator_SystemPermission_NoRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{
			"readonly": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	tests := []struct {
		name       string
		authCtx    AuthContext
		permission Permission
	}{
		{
			name: "user without system role",
			authCtx: &UserAuthContext{
				UniqueID: "user-1",
				Groups:   []string{"READERS"},
			},
			permission: Permission{Resource: "system", Action: "admin"},
		},
		{
			name: "machine without system role",
			authCtx: &MachineAuthContext{
				ServicePrincipalID: "sp-1",
				Roles:              []string{"readonly"},
			},
			permission: Permission{Resource: "system", Action: "write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorized, reason := evaluator.Evaluate(tt.authCtx, tt.permission, ResourceContext{})
			assert.False(t, authorized)
			assert.Equal(t, "system_permission_denied", reason)
		})
	}
}

// ============================================================================
// 4.2 User Permission Evaluation - Non-Unit-Scoped
// ============================================================================

func TestEvaluator_User_GlobalPermission_Granted(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
		Units:    []string{"unit-1"},
	}

	// Resource without unitID - global permission check
	resource := ResourceContext{}

	authorized, reason := evaluator.Evaluate(userCtx, Permission{Resource: "app", Action: "read"}, resource)
	assert.True(t, authorized)
	assert.Equal(t, "user_role_admin", reason)
}

func TestEvaluator_User_GlobalPermission_Denied(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{
			"readonly": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"READERS"},
	}

	resource := ResourceContext{}

	authorized, reason := evaluator.Evaluate(userCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized)
	assert.Equal(t, "user_not_authorized", reason)
}

func TestEvaluator_User_MultipleRoles(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"GROUP-A": {"admin"},
			"GROUP-B": {"readonly"},
			"GROUP-C": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "delete"},
			},
			"readonly": {
				{Resource: "app", Action: "read"},
			},
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	tests := []struct {
		name       string
		groups     []string
		permission Permission
		wantAuth   bool
	}{
		{
			name:       "user with admin group can delete",
			groups:     []string{"GROUP-A"},
			permission: Permission{Resource: "app", Action: "delete"},
			wantAuth:   true,
		},
		{
			name:       "user with readonly group can read",
			groups:     []string{"GROUP-B"},
			permission: Permission{Resource: "app", Action: "read"},
			wantAuth:   true,
		},
		{
			name:       "user with multiple groups - any grants access",
			groups:     []string{"GROUP-B", "GROUP-C"},
			permission: Permission{Resource: "app", Action: "write"},
			wantAuth:   true,
		},
		{
			name:       "user without required permission",
			groups:     []string{"GROUP-B"},
			permission: Permission{Resource: "app", Action: "delete"},
			wantAuth:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx := &UserAuthContext{
				UniqueID: "user-1",
				Groups:   tt.groups,
			}
			authorized, _ := evaluator.Evaluate(userCtx, tt.permission, ResourceContext{})
			assert.Equal(t, tt.wantAuth, authorized)
		})
	}
}

// ============================================================================
// 4.3 User Permission Evaluation - Unit-Scoped (CRITICAL SECURITY TESTS)
// ============================================================================

func TestEvaluator_User_UnitScoped_MatchingUnit(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-CREATORS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	tests := []struct {
		name         string
		userUnits    []string
		resourceUnit string
		permission   Permission
		wantAuth     bool
		wantReason   string
	}{
		{
			name:         "user unit matches resource unit",
			userUnits:    []string{"unit-123"},
			resourceUnit: "unit-123",
			permission:   Permission{Resource: "app", Action: "write"},
			wantAuth:     true,
			wantReason:   "user_unit_match_app.creator",
		},
		{
			name:         "user has multiple units, one matches",
			userUnits:    []string{"unit-123", "unit-456"},
			resourceUnit: "unit-456",
			permission:   Permission{Resource: "app", Action: "write"},
			wantAuth:     true,
			wantReason:   "user_unit_match_app.creator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx := &UserAuthContext{
				UniqueID: "user-1",
				Groups:   []string{"APP-CREATORS"},
				Units:    tt.userUnits,
			}

			resource := ResourceContext{
				"unitID": tt.resourceUnit,
			}

			authorized, reason := evaluator.Evaluate(userCtx, tt.permission, resource)
			assert.Equal(t, tt.wantAuth, authorized)
			assert.Equal(t, tt.wantReason, reason)
		})
	}
}

func TestEvaluator_User_UnitScoped_NoMatchingUnit(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-CREATORS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"APP-CREATORS"},
		Units:    []string{"unit-123"},
	}

	resource := ResourceContext{
		"unitID": "unit-456",
	}

	authorized, reason := evaluator.Evaluate(userCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized)
	assert.Equal(t, "user_unit_mismatch_required_unit-456", reason)
}

func TestEvaluator_User_UnitScoped_MultipleUnits(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-CREATORS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"APP-CREATORS"},
		Units:    []string{"unit-123", "unit-456", "unit-789"},
	}

	resource := ResourceContext{
		"unitID": "unit-456",
	}

	authorized, reason := evaluator.Evaluate(userCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.True(t, authorized)
	assert.Equal(t, "user_unit_match_app.creator", reason)
}

// CRITICAL SECURITY TEST
func TestEvaluator_User_UnitScoped_GlobalPermissionDoesNotBypass(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "app", Action: "delete"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	// User with global admin permissions but wrong unit
	userCtx := &UserAuthContext{
		UniqueID: "admin-user",
		Groups:   []string{"ADMINS"},
		Units:    []string{"unit-123"},
	}

	// Resource requires unit-456
	resource := ResourceContext{
		"unitID": "unit-456",
	}

	// MUST BE DENIED - Global permissions cannot bypass unit scoping
	authorized, reason := evaluator.Evaluate(userCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized, "CRITICAL: Global admin permission MUST NOT bypass unit scoping")
	assert.Equal(t, "user_unit_mismatch_required_unit-456", reason)
}

func TestEvaluator_User_UnitScoped_NoUnitScopedPermission(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{
			"readonly": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	// User has matching unit but role doesn't have unit-scoped permissions
	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"READERS"},
		Units:    []string{"unit-123"},
	}

	resource := ResourceContext{
		"unitID": "unit-123",
	}

	// Should be denied because readonly role doesn't have unit-scoped write permission
	authorized, reason := evaluator.Evaluate(userCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized)
	assert.Contains(t, reason, "user_unit_mismatch")
}

// ============================================================================
// 4.4 Machine Permission Evaluation - Non-Unit-Scoped
// ============================================================================

func TestEvaluator_Machine_GlobalPermission_Granted(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"service.principal": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
		ClientID:           "client-456",
		Roles:              []string{"service.principal"},
	}

	resource := ResourceContext{}

	authorized, reason := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.True(t, authorized)
	assert.Equal(t, "machine_role_service.principal", reason)
}

func TestEvaluator_Machine_GlobalPermission_ViaGroups(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"AppRole1": {"service.principal"},
		},
		RolePermissions: map[string][]Permission{
			"service.principal": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
		ClientID:           "client-456",
		Groups:             []string{"AppRole1"},
	}

	resource := ResourceContext{}

	authorized, reason := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "read"}, resource)
	assert.True(t, authorized)
	assert.Equal(t, "machine_group_role_service.principal", reason)
}

func TestEvaluator_Machine_CombinedRoles(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"AppRole1": {"readonly"},
		},
		RolePermissions: map[string][]Permission{
			"service.principal": {
				{Resource: "app", Action: "write"},
			},
			"readonly": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
		Roles:              []string{"service.principal"},
		Groups:             []string{"AppRole1"},
	}

	resource := ResourceContext{}

	// Should have access via direct role
	authorized1, reason1 := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.True(t, authorized1)
	assert.Equal(t, "machine_role_service.principal", reason1)

	// Should have access via group role
	authorized2, reason2 := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "read"}, resource)
	assert.True(t, authorized2)
	// Could be either machine_role or machine_group_role depending on order
	assert.True(t, reason2 == "machine_role_service.principal" || reason2 == "machine_group_role_readonly")
}

// ============================================================================
// 4.5 Machine Permission Evaluation - Unit-Scoped (CRITICAL SECURITY TESTS)
// ============================================================================

func TestEvaluator_Machine_UnitScoped_WithResolver_MatchingUnit(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
		ClientID:           "client-456",
		Roles:              []string{"app.creator"},
	}

	// Resource with machineUnits populated by resolver
	resource := ResourceContext{
		"unitID":       "unit-123",
		"machineUnits": "unit-123,unit-456",
	}

	authorized, reason := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.True(t, authorized)
	assert.Equal(t, "machine_unit_match_app.creator", reason)
}

func TestEvaluator_Machine_UnitScoped_WithResolver_NoMatch(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
		Roles:              []string{"app.creator"},
	}

	resource := ResourceContext{
		"unitID":       "unit-999",
		"machineUnits": "unit-123,unit-456",
	}

	authorized, reason := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized)
	assert.Equal(t, "machine_unit_mismatch_required_unit-999", reason)
}

func TestEvaluator_Machine_UnitScoped_WithoutResolver(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
		Roles:              []string{"app.creator"},
	}

	// Resource has unitID but machineUnits not populated (no resolver)
	resource := ResourceContext{
		"unitID": "unit-123",
	}

	authorized, reason := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized)
	assert.Equal(t, "machine_unit_required_unit-123", reason)
}

func TestEvaluator_Machine_UnitScoped_EmptyMachineUnits(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-123",
		Roles:              []string{"app.creator"},
	}

	resource := ResourceContext{
		"unitID":       "unit-123",
		"machineUnits": "",
	}

	authorized, reason := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized)
	assert.Equal(t, "machine_unit_required_unit-123", reason)
}

// CRITICAL SECURITY TEST
func TestEvaluator_Machine_UnitScoped_GlobalPermissionDoesNotBypass(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "app", Action: "delete"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	// Machine with global admin permissions
	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-admin",
		ClientID:           "client-admin",
		Roles:              []string{"admin"},
	}

	// Resource is unit-scoped, machine has different units
	resource := ResourceContext{
		"unitID":       "unit-456",
		"machineUnits": "unit-123,unit-789",
	}

	// MUST BE DENIED - Global permissions cannot bypass unit scoping
	authorized, reason := evaluator.Evaluate(machineCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized, "CRITICAL: Global admin permission MUST NOT bypass unit scoping for machines")
	assert.Equal(t, "machine_unit_mismatch_required_unit-456", reason)
}

// ============================================================================
// 4.6 Helper Function Tests
// ============================================================================

func TestEvaluator_GetRoles_User(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"GROUP-A": {"admin", "readonly"},
			"GROUP-B": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"GROUP-A", "GROUP-B"},
	}

	roles := evaluator.getRoles(userCtx)
	assert.ElementsMatch(t, []string{"admin", "readonly", "app.creator"}, roles)
}

func TestEvaluator_GetRoles_Machine(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"AppRole1": {"readonly"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	tests := []struct {
		name          string
		directRoles   []string
		groups        []string
		expectedRoles []string
	}{
		{
			name:          "direct roles only",
			directRoles:   []string{"service.principal", "admin"},
			groups:        []string{},
			expectedRoles: []string{"service.principal", "admin"},
		},
		{
			name:          "group roles only",
			directRoles:   []string{},
			groups:        []string{"AppRole1"},
			expectedRoles: []string{"readonly"},
		},
		{
			name:          "combined roles with deduplication",
			directRoles:   []string{"admin", "readonly"},
			groups:        []string{"AppRole1"},
			expectedRoles: []string{"admin", "readonly"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machineCtx := &MachineAuthContext{
				ServicePrincipalID: "sp-1",
				Roles:              tt.directRoles,
				Groups:             tt.groups,
			}

			roles := evaluator.getRoles(machineCtx)
			assert.ElementsMatch(t, tt.expectedRoles, roles)
		})
	}
}

func TestEvaluator_HasUnitScopedPermission(t *testing.T) {
	evaluator := NewPolicyEvaluator(nil, nil)

	tests := []struct {
		name       string
		role       string
		permission Permission
		want       bool
	}{
		{
			name:       "app.creator has app:write",
			role:       "app.creator",
			permission: Permission{Resource: "app", Action: "write"},
			want:       true,
		},
		{
			name:       "app.creator has secret:write",
			role:       "app.creator",
			permission: Permission{Resource: "secret", Action: "write"},
			want:       true,
		},
		{
			name:       "admin has unit-scoped permissions",
			role:       "admin",
			permission: Permission{Resource: "app", Action: "write"},
			want:       true,
		},
		{
			name:       "readonly does not have unit-scoped permissions",
			role:       "readonly",
			permission: Permission{Resource: "app", Action: "read"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluator.hasUnitScopedPermission(tt.role, tt.permission)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEvaluator_SplitString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		delimiter string
		want      []string
	}{
		{
			name:      "single value",
			input:     "unit-123",
			delimiter: ",",
			want:      []string{"unit-123"},
		},
		{
			name:      "multiple values",
			input:     "unit-123,unit-456,unit-789",
			delimiter: ",",
			want:      []string{"unit-123", "unit-456", "unit-789"},
		},
		{
			name:      "different delimiter",
			input:     "a;b;c",
			delimiter: ";",
			want:      []string{"a", "b", "c"},
		},
		{
			name:      "delimiter at end",
			input:     "a,b,",
			delimiter: ",",
			want:      []string{"a", "b", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Split(tt.input, tt.delimiter)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEvaluator_NewPolicyEvaluator_Defaults(t *testing.T) {
	// Test with nil config
	evaluator1 := NewPolicyEvaluator(nil, nil)
	assert.NotNil(t, evaluator1.config)
	assert.NotNil(t, evaluator1.log)

	// Test with custom config
	customConfig := &Config{
		RolePermissions: map[string][]Permission{
			"custom": {{Resource: "test", Action: "test"}},
		},
	}
	evaluator2 := NewPolicyEvaluator(customConfig, nil)
	assert.Equal(t, customConfig, evaluator2.config)
	assert.NotNil(t, evaluator2.log)

	// Test with custom logger
	logger := zap.NewNop()
	evaluator3 := NewPolicyEvaluator(nil, logger)
	assert.Equal(t, logger, evaluator3.log)
}

// ============================================================================
// Edge Cases and Additional Tests
// ============================================================================

func TestEvaluator_EmptyGroups(t *testing.T) {
	config := GetDefaultConfig()
	evaluator := NewPolicyEvaluator(config, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{},
	}

	authorized, reason := evaluator.Evaluate(userCtx, Permission{Resource: "app", Action: "read"}, ResourceContext{})
	assert.False(t, authorized)
	assert.Equal(t, "user_not_authorized", reason)
}

func TestEvaluator_NoUnits(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-CREATORS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)

	// User with no units trying to access unit-scoped resource
	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"APP-CREATORS"},
		Units:    []string{},
	}

	resource := ResourceContext{
		"unitID": "unit-123",
	}

	authorized, reason := evaluator.Evaluate(userCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.False(t, authorized)
	assert.Equal(t, "user_unit_mismatch_required_unit-123", reason)
}
