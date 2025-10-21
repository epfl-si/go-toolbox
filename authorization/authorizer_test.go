package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// ============================================================================
// 5.1 SimpleAuthorizer - HasRole
// ============================================================================

func TestSimpleAuthorizer_HasRole_User_WithRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS":  {"admin"},
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}

	assert.True(t, authorizer.HasRole(userCtx, "admin"))
	assert.False(t, authorizer.HasRole(userCtx, "readonly"))
}

func TestSimpleAuthorizer_HasRole_User_WithoutRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"READERS"},
	}

	assert.False(t, authorizer.HasRole(userCtx, "admin"))
}

func TestSimpleAuthorizer_HasRole_Machine_DirectRole(t *testing.T) {
	config := &Config{
		GroupMappings:   map[string][]string{},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-1",
		Roles:              []string{"service.principal", "admin"},
	}

	assert.True(t, authorizer.HasRole(machineCtx, "service.principal"))
	assert.True(t, authorizer.HasRole(machineCtx, "admin"))
	assert.False(t, authorizer.HasRole(machineCtx, "readonly"))
}

func TestSimpleAuthorizer_HasRole_Machine_NoRole(t *testing.T) {
	config := &Config{
		GroupMappings:   map[string][]string{},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-1",
		Roles:              []string{},
	}

	assert.False(t, authorizer.HasRole(machineCtx, "admin"))
}

// ============================================================================
// 5.2 SimpleAuthorizer - HasPermission
// ============================================================================

func TestSimpleAuthorizer_HasPermission_WithEnhancer(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
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

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-1",
		Roles:              []string{"app.creator"},
	}

	resource := ResourceContext{
		"appID":        "app-1",
		"unitID":       "unit-123",
		"machineUnits": "unit-123,unit-456", // Pre-enhanced resource
	}

	authorized, err := authorizer.HasPermission(context.Background(), machineCtx, Permission{Resource: "app", Action: "write"}, resource)
	assert.NoError(t, err)
	assert.True(t, authorized)
}

func TestSimpleAuthorizer_HasPermission_WithoutEnhancer(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}

	resource := ResourceContext{}

	authorized, err := authorizer.HasPermission(context.Background(), userCtx, Permission{Resource: "app", Action: "read"}, resource)
	assert.NoError(t, err)
	assert.True(t, authorized)
}

func TestSimpleAuthorizer_HasPermission_Authorized(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}

	authorized, err := authorizer.HasPermission(context.Background(), userCtx, Permission{Resource: "app", Action: "write"}, ResourceContext{})
	assert.NoError(t, err)
	assert.True(t, authorized)
}

func TestSimpleAuthorizer_HasPermission_Denied(t *testing.T) {
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
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"READERS"},
	}

	authorized, err := authorizer.HasPermission(context.Background(), userCtx, Permission{Resource: "app", Action: "write"}, ResourceContext{})
	assert.NoError(t, err)
	assert.False(t, authorized)
}

// ============================================================================
// 5.3 AuthorizerBuilder
// ============================================================================

func TestAuthorizerBuilder_WithConfig(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"custom": {{Resource: "test", Action: "test"}},
		},
	}

	authorizer := NewAuthorizerBuilder().
		WithConfig(config).
		Build()

	assert.NotNil(t, authorizer)
	assert.Equal(t, config, authorizer.evaluator.config)
}

func TestAuthorizerBuilder_WithLogger(t *testing.T) {
	logger := zap.NewNop()

	authorizer := NewAuthorizerBuilder().
		WithLogger(logger).
		Build()

	assert.NotNil(t, authorizer)
	assert.Equal(t, logger, authorizer.log)
}

func TestAuthorizerBuilder_Defaults(t *testing.T) {
	authorizer := NewAuthorizerBuilder().Build()

	assert.NotNil(t, authorizer)
	assert.NotNil(t, authorizer.evaluator)
	assert.NotNil(t, authorizer.log)
}

func TestAuthorizerBuilder_ChainedCalls(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"test": {{Resource: "test", Action: "test"}},
		},
	}
	logger := zap.NewNop()

	authorizer := NewAuthorizerBuilder().
		WithConfig(config).
		WithLogger(logger).
		Build()

	assert.NotNil(t, authorizer)
	assert.Equal(t, config, authorizer.evaluator.config)
	assert.Equal(t, logger, authorizer.log)
}

func TestNewSimpleAuthorizer_NilInputs(t *testing.T) {
	// Test with all nil inputs
	authorizer := NewSimpleAuthorizer(nil, nil)

	assert.NotNil(t, authorizer)
	assert.NotNil(t, authorizer.evaluator)
	assert.NotNil(t, authorizer.log)
}

func TestNewSimpleAuthorizer_CustomInputs(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"test": {{Resource: "test", Action: "test"}},
		},
	}
	evaluator := NewPolicyEvaluator(config, nil)
	logger := zap.NewNop()

	authorizer := NewSimpleAuthorizer(evaluator, logger)

	assert.NotNil(t, authorizer)
	assert.Equal(t, evaluator, authorizer.evaluator)
	assert.Equal(t, logger, authorizer.log)
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestSimpleAuthorizer_Integration_UserFlow(t *testing.T) {
	// Create a custom config for this test to ensure app.creator doesn't have global app:write
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-PORTAL-ADMINS-PROD":  {"admin"},
			"APP-PORTAL-READERS-PROD": {"readonly"},
			"APP-CREATORS-DEPT-A":     {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "app", Action: "delete"},
				{Resource: "app", Action: "manage"},
			},
			"readonly": {
				{Resource: "app", Action: "read"},
			},
			// app.creator has no global app:write permission
		},
		UnitScopedRoles: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	tests := []struct {
		name       string
		userCtx    *UserAuthContext
		permission Permission
		resource   ResourceContext
		wantAuth   bool
	}{
		{
			name: "admin can read apps",
			userCtx: &UserAuthContext{
				UniqueID: "admin-user",
				Groups:   []string{"APP-PORTAL-ADMINS-PROD"},
			},
			permission: Permission{Resource: "app", Action: "read"},
			resource:   ResourceContext{},
			wantAuth:   true,
		},
		{
			name: "readonly cannot write apps",
			userCtx: &UserAuthContext{
				UniqueID: "readonly-user",
				Groups:   []string{"APP-PORTAL-READERS-PROD"},
			},
			permission: Permission{Resource: "app", Action: "write"},
			resource:   ResourceContext{},
			wantAuth:   false,
		},
		{
			name: "app.creator can write with matching unit via unit-scoped permission",
			userCtx: &UserAuthContext{
				UniqueID: "creator-user",
				Groups:   []string{"APP-CREATORS-DEPT-A"},
				Units:    []string{"unit-123"},
			},
			permission: Permission{Resource: "app", Action: "write"},
			resource: ResourceContext{
				"unitID": "unit-123",
			},
			wantAuth: true,
		},
		{
			name: "app.creator cannot write with wrong unit when no global permission",
			userCtx: &UserAuthContext{
				UniqueID: "creator-user",
				Groups:   []string{"APP-CREATORS-DEPT-A"},
				Units:    []string{"unit-123"},
			},
			permission: Permission{Resource: "app", Action: "write"},
			resource: ResourceContext{
				"unitID": "unit-456",
			},
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorized, err := authorizer.HasPermission(context.Background(), tt.userCtx, tt.permission, tt.resource)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAuth, authorized)
		})
	}
}

func TestSimpleAuthorizer_Integration_MachineFlow(t *testing.T) {
	// Create a custom config for this test to ensure app.creator doesn't have global app:write
	config := &Config{
		RolePermissions: map[string][]Permission{
			"service.principal": {
				{Resource: "app", Action: "read"},
			},
			// app.creator has no global app:write permission
		},
		UnitScopedRoles: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	tests := []struct {
		name       string
		machineCtx *MachineAuthContext
		permission Permission
		resource   ResourceContext
		wantAuth   bool
	}{
		{
			name: "service principal can read apps",
			machineCtx: &MachineAuthContext{
				ServicePrincipalID: "sp-1",
				Roles:              []string{"service.principal"},
			},
			permission: Permission{Resource: "app", Action: "read"},
			resource:   ResourceContext{},
			wantAuth:   true,
		},
		{
			name: "machine with unit access can write via unit-scoped permission",
			machineCtx: &MachineAuthContext{
				ServicePrincipalID: "sp-2",
				Roles:              []string{"app.creator"},
			},
			permission: Permission{Resource: "app", Action: "write"},
			resource: ResourceContext{
				"appID":        "app-1",
				"unitID":       "unit-123",
				"machineUnits": "unit-123,unit-456", // Pre-enhanced resource
			},
			wantAuth: true,
		},
		{
			name: "machine without unit access cannot write when no global permission",
			machineCtx: &MachineAuthContext{
				ServicePrincipalID: "sp-3",
				Roles:              []string{"app.creator"},
			},
			permission: Permission{Resource: "app", Action: "write"},
			resource: ResourceContext{
				"appID":        "app-1",
				"unitID":       "unit-999",
				"machineUnits": "unit-123,unit-456", // Pre-enhanced resource
			},
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorized, err := authorizer.HasPermission(context.Background(), tt.machineCtx, tt.permission, tt.resource)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAuth, authorized)
		})
	}
}
