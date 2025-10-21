package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestGlobalRoleBypass verifies that users with global permissions can access
// unit-scoped resources regardless of their unit assignments
func TestGlobalRoleBypass(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS":       {"admin"},
			"UNIT_ADMINS":  {"unit.admin"},
			"APP_CREATORS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "app", Action: "delete"},
				{Resource: "app", Action: "manage"},
				{Resource: "unit", Action: "read"},
				{Resource: "unit", Action: "write"},
				{Resource: "secret", Action: "read"},
				{Resource: "secret", Action: "write"},
			},
		},
		UnitScopedRoles: map[string][]Permission{
			"unit.admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "app", Action: "delete"},
				{Resource: "app", Action: "manage"},
				{Resource: "secret", Action: "read"},
				{Resource: "secret", Action: "write"},
			},
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "secret", Action: "write"},
			},
		},
	}

	logger, _ := zap.NewDevelopment()
	evaluator := NewPolicyEvaluator(config, logger)

	tests := []struct {
		name         string
		authCtx      AuthContext
		permission   Permission
		resourceUnit string
		wantAuth     bool
		wantReason   string
	}{
		{
			name: "admin can access any unit via global bypass",
			authCtx: &UserAuthContext{
				UniqueID: "admin-user",
				Groups:   []string{"ADMINS"},
				Units:    []string{"16000"},
			},
			permission:   Permission{Resource: "unit", Action: "write"},
			resourceUnit: "99999", // Unit not in user's units
			wantAuth:     true,
			wantReason:   "user_global_role_bypass_admin",
		},
		{
			name: "admin can access own unit via global bypass",
			authCtx: &UserAuthContext{
				UniqueID: "admin-user",
				Groups:   []string{"ADMINS"},
				Units:    []string{"16000"},
			},
			permission:   Permission{Resource: "unit", Action: "write"},
			resourceUnit: "16000", // Unit in user's units
			wantAuth:     true,
			wantReason:   "user_global_role_bypass_admin",
		},
		{
			name: "unit admin can access own unit via unit-scoped permission",
			authCtx: &UserAuthContext{
				UniqueID: "unit-admin",
				Groups:   []string{"UNIT_ADMINS"},
				Units:    []string{"16000"},
			},
			permission:   Permission{Resource: "app", Action: "write"},
			resourceUnit: "16000", // Unit in user's units
			wantAuth:     true,
			wantReason:   "user_unit_match_unit.admin",
		},
		{
			name: "unit admin cannot access other unit",
			authCtx: &UserAuthContext{
				UniqueID: "unit-admin",
				Groups:   []string{"UNIT_ADMINS"},
				Units:    []string{"16000"},
			},
			permission:   Permission{Resource: "app", Action: "write"},
			resourceUnit: "99999", // Unit not in user's units
			wantAuth:     false,
			wantReason:   "user_unit_mismatch_required_99999",
		},
		{
			name: "app creator cannot perform unit:write even on own unit",
			authCtx: &UserAuthContext{
				UniqueID: "app-creator",
				Groups:   []string{"APP_CREATORS"},
				Units:    []string{"16000"},
			},
			permission:   Permission{Resource: "unit", Action: "write"},
			resourceUnit: "16000", // Unit in user's units
			wantAuth:     false,
			wantReason:   "user_unit_mismatch_required_16000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := ResourceContext{
				"unitID": tt.resourceUnit,
			}

			authorized, reason := evaluator.Evaluate(tt.authCtx, tt.permission, resource)
			assert.Equal(t, tt.wantAuth, authorized, "Authorization result mismatch")
			assert.Equal(t, tt.wantReason, reason, "Reason mismatch")
		})
	}
}

// TestMachineGlobalRoleBypass verifies that machines with global permissions can access
// unit-scoped resources regardless of their unit assignments
func TestMachineGlobalRoleBypass(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "app", Action: "delete"},
				{Resource: "app", Action: "manage"},
				{Resource: "unit", Action: "read"},
				{Resource: "unit", Action: "write"},
				{Resource: "secret", Action: "read"},
				{Resource: "secret", Action: "write"},
			},
			"service.principal": {
				{Resource: "app", Action: "read"},
			},
		},
		UnitScopedRoles: map[string][]Permission{
			"service.principal": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	logger, _ := zap.NewDevelopment()
	evaluator := NewPolicyEvaluator(config, logger)

	tests := []struct {
		name         string
		authCtx      AuthContext
		permission   Permission
		resourceUnit string
		machineUnits string
		wantAuth     bool
		wantReason   string
	}{
		{
			name: "admin machine can access any unit via global bypass",
			authCtx: &MachineAuthContext{
				ServicePrincipalID: "admin-sp",
				ClientID:           "admin-client",
				Roles:              []string{"admin"},
				AllowedUnits:       []string{"16000"},
			},
			permission:   Permission{Resource: "unit", Action: "write"},
			resourceUnit: "99999", // Unit not in machine's units
			machineUnits: "16000", // Machine units from resolver
			wantAuth:     true,
			wantReason:   "machine_global_role_bypass_admin",
		},
		{
			name: "service principal cannot access unit without permission",
			authCtx: &MachineAuthContext{
				ServicePrincipalID: "service-sp",
				ClientID:           "service-client",
				Roles:              []string{"service.principal"},
				AllowedUnits:       []string{"16000"},
			},
			permission:   Permission{Resource: "unit", Action: "write"},
			resourceUnit: "16000", // Unit in machine's units
			machineUnits: "16000", // Machine units from resolver
			wantAuth:     false,
			wantReason:   "machine_unit_match_no_permission_16000",
		},
		{
			name: "service principal can access own unit for allowed permission",
			authCtx: &MachineAuthContext{
				ServicePrincipalID: "service-sp",
				ClientID:           "service-client",
				Roles:              []string{"service.principal"},
				AllowedUnits:       []string{"16000"},
			},
			permission:   Permission{Resource: "app", Action: "read"},
			resourceUnit: "16000", // Unit in machine's units
			machineUnits: "16000", // Machine units from resolver
			wantAuth:     true,
			wantReason:   "machine_global_role_bypass_service.principal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := ResourceContext{
				"unitID":       tt.resourceUnit,
				"machineUnits": tt.machineUnits,
			}

			authorized, reason := evaluator.Evaluate(tt.authCtx, tt.permission, resource)
			assert.Equal(t, tt.wantAuth, authorized, "Authorization result mismatch")
			assert.Equal(t, tt.wantReason, reason, "Reason mismatch")
		})
	}
}
