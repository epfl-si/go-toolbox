package authorization

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// 1.1 Config Loading Tests
// ============================================================================

func TestConfig_LoadFromFile_ValidConfig(t *testing.T) {
	// Create a temporary JSON config file with valid structure
	configJSON := `{
		"rolePermissions": {
			"admin": [
				{"resource": "app", "action": "read"},
				{"resource": "app", "action": "write"}
			],
			"readonly": [
				{"resource": "app", "action": "read"}
			]
		},
		"groupMappings": {
			"APP-ADMINS": ["admin"],
			"APP-READERS": ["readonly"]
		}
	}`

	// Create temp file
	tmpFile, err := os.CreateTemp("", "config-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(configJSON)
	require.NoError(t, err)
	tmpFile.Close()

	// Load config from file
	config := NewConfig()
	err = config.LoadFromFile(tmpFile.Name())
	require.NoError(t, err)

	// Verify RolePermissions are correctly parsed
	assert.Contains(t, config.RolePermissions, "admin")
	assert.Contains(t, config.RolePermissions, "readonly")
	assert.Len(t, config.RolePermissions["admin"], 2)
	assert.Len(t, config.RolePermissions["readonly"], 1)

	// Verify GroupMappings are correctly parsed
	assert.Contains(t, config.GroupMappings, "APP-ADMINS")
	assert.Contains(t, config.GroupMappings, "APP-READERS")
	assert.Equal(t, []string{"admin"}, config.GroupMappings["APP-ADMINS"])
	assert.Equal(t, []string{"readonly"}, config.GroupMappings["APP-READERS"])
}

func TestConfig_LoadFromFile_InvalidPath(t *testing.T) {
	config := NewConfig()
	err := config.LoadFromFile("/non/existent/path/config.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open config file")
}

func TestConfig_LoadFromReader_InvalidJSON(t *testing.T) {
	config := NewConfig()
	invalidJSON := `{"rolePermissions": {invalid json}}`
	reader := strings.NewReader(invalidJSON)

	err := config.LoadFromReader(reader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode config")
}

func TestConfig_LoadFromReader_ValidJSON(t *testing.T) {
	tests := []struct {
		name        string
		jsonInput   string
		wantErr     bool
		checkRoles  map[string]bool
		checkGroups map[string][]string
	}{
		{
			name: "valid config with admin role",
			jsonInput: `{
				"rolePermissions": {
					"admin": [
						{"resource": "app", "action": "read"},
						{"resource": "app", "action": "write"}
					]
				},
				"groupMappings": {
					"APP-ADMINS": ["admin"]
				}
			}`,
			wantErr: false,
			checkRoles: map[string]bool{
				"admin": true,
			},
			checkGroups: map[string][]string{
				"APP-ADMINS": {"admin"},
			},
		},
		{
			name: "multiple roles and groups",
			jsonInput: `{
				"rolePermissions": {
					"admin": [{"resource": "system", "action": "admin"}],
					"readonly": [{"resource": "app", "action": "read"}]
				},
				"groupMappings": {
					"ADMINS": ["admin"],
					"READERS": ["readonly"]
				}
			}`,
			wantErr: false,
			checkRoles: map[string]bool{
				"admin":    true,
				"readonly": true,
			},
			checkGroups: map[string][]string{
				"ADMINS":  {"admin"},
				"READERS": {"readonly"},
			},
		},
		{
			name: "empty config",
			jsonInput: `{
				"rolePermissions": {},
				"groupMappings": {}
			}`,
			wantErr:     false,
			checkRoles:  map[string]bool{},
			checkGroups: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConfig()
			reader := strings.NewReader(tt.jsonInput)
			err := config.LoadFromReader(reader)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Check roles exist
			for role := range tt.checkRoles {
				_, exists := config.RolePermissions[role]
				assert.True(t, exists, "Role %s should exist", role)
			}

			// Check group mappings
			for group, expectedRoles := range tt.checkGroups {
				actualRoles := config.GetRolesForGroup(group)
				assert.ElementsMatch(t, expectedRoles, actualRoles)
			}
		})
	}
}

// ============================================================================
// 1.2 Role Permission Checks
// ============================================================================

func TestConfig_HasRolePermission_RoleExists(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "system", Action: "admin"},
			},
			"readonly": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	tests := []struct {
		name       string
		role       string
		permission Permission
		want       bool
	}{
		{
			name:       "admin has app:read",
			role:       "admin",
			permission: Permission{Resource: "app", Action: "read"},
			want:       true,
		},
		{
			name:       "admin has app:write",
			role:       "admin",
			permission: Permission{Resource: "app", Action: "write"},
			want:       true,
		},
		{
			name:       "admin has system:admin",
			role:       "admin",
			permission: Permission{Resource: "system", Action: "admin"},
			want:       true,
		},
		{
			name:       "admin does not have app:delete",
			role:       "admin",
			permission: Permission{Resource: "app", Action: "delete"},
			want:       false,
		},
		{
			name:       "readonly has app:read",
			role:       "readonly",
			permission: Permission{Resource: "app", Action: "read"},
			want:       true,
		},
		{
			name:       "readonly does not have app:write",
			role:       "readonly",
			permission: Permission{Resource: "app", Action: "write"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.HasRolePermission(tt.role, tt.permission)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_HasRolePermission_RoleNotExists(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	// Query non-existent role
	got := config.HasRolePermission("nonexistent", Permission{Resource: "app", Action: "read"})
	assert.False(t, got)
}

// ============================================================================
// 1.3 Group to Role Mapping
// ============================================================================

func TestConfig_GetRolesForGroup_SingleRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-ADMINS": {"admin"},
		},
	}

	roles := config.GetRolesForGroup("APP-ADMINS")
	assert.Equal(t, []string{"admin"}, roles)
}

func TestConfig_GetRolesForGroup_MultipleRoles(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-CREATORS": {"app.creator", "app.reader"},
		},
	}

	roles := config.GetRolesForGroup("APP-CREATORS")
	assert.ElementsMatch(t, []string{"app.creator", "app.reader"}, roles)
}

func TestConfig_GetRolesForGroup_NonExistentGroup(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-ADMINS": {"admin"},
		},
	}

	roles := config.GetRolesForGroup("NONEXISTENT")
	assert.Nil(t, roles)
}

func TestConfig_GetRolesForGroups_Deduplication(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"GROUP-A": {"admin", "readonly"},
			"GROUP-B": {"admin", "app.creator"},
			"GROUP-C": {"readonly"},
		},
	}

	tests := []struct {
		name   string
		groups []string
		want   []string
	}{
		{
			name:   "overlapping roles are deduplicated",
			groups: []string{"GROUP-A", "GROUP-B"},
			want:   []string{"admin", "readonly", "app.creator"},
		},
		{
			name:   "all three groups with deduplication",
			groups: []string{"GROUP-A", "GROUP-B", "GROUP-C"},
			want:   []string{"admin", "readonly", "app.creator"},
		},
		{
			name:   "single group",
			groups: []string{"GROUP-A"},
			want:   []string{"admin", "readonly"},
		},
		{
			name:   "no groups",
			groups: []string{},
			want:   []string{},
		},
		{
			name:   "non-existent group",
			groups: []string{"NONEXISTENT"},
			want:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.GetRolesForGroups(tt.groups)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestConfig_GetDefaultConfig(t *testing.T) {
	config := GetDefaultConfig()

	// Verify standard roles are present
	assert.Contains(t, config.RolePermissions, "admin")
	assert.Contains(t, config.RolePermissions, "readonly")
	assert.Contains(t, config.RolePermissions, "app.creator")
	assert.Contains(t, config.RolePermissions, "app.reader")
	assert.Contains(t, config.RolePermissions, "service.principal")

	// Verify group mappings are populated
	assert.Contains(t, config.GroupMappings, "APP-PORTAL-ADMINS-PROD")
	assert.Contains(t, config.GroupMappings, "APP-PORTAL-READERS-PROD")
	assert.Contains(t, config.GroupMappings, "APP-CREATORS-DEPT-A")

	// Verify admin has comprehensive permissions
	adminPerms := config.RolePermissions["admin"]
	assert.NotEmpty(t, adminPerms)

	// Check that admin has key permissions
	hasAppRead := false
	hasAppWrite := false
	hasSystemAdmin := false
	for _, p := range adminPerms {
		if p.Resource == "app" && p.Action == "read" {
			hasAppRead = true
		}
		if p.Resource == "app" && p.Action == "write" {
			hasAppWrite = true
		}
		if p.Resource == "system" && p.Action == "admin" {
			hasSystemAdmin = true
		}
	}
	assert.True(t, hasAppRead, "admin should have app:read")
	assert.True(t, hasAppWrite, "admin should have app:write")
	assert.True(t, hasSystemAdmin, "admin should have system:admin")

	// Verify readonly has limited permissions
	readonlyPerms := config.RolePermissions["readonly"]
	assert.NotEmpty(t, readonlyPerms)
	for _, p := range readonlyPerms {
		assert.Equal(t, "read", p.Action, "readonly should only have read permissions")
	}
}

func TestConfig_NewConfig(t *testing.T) {
	config := NewConfig()

	assert.NotNil(t, config)
	assert.NotNil(t, config.RolePermissions)
	assert.NotNil(t, config.GroupMappings)
	assert.Empty(t, config.RolePermissions)
	assert.Empty(t, config.GroupMappings)
}
