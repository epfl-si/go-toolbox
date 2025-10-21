package authorization

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Config Loading Tests
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
	assert.Contains(t, err.Error(), "failed to decode JSON config")
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
// YAML Config Loading Tests
// ============================================================================

func TestConfig_LoadFromFile_ValidYAMLConfig(t *testing.T) {
	// Create a temporary YAML config file with valid structure
	configYAML := `
# Test YAML Configuration
rolePermissions:
  admin:
    - resource: app
      action: read
    - resource: app
      action: write
  readonly:
    - resource: app
      action: read
groupMappings:
  APP-ADMINS:
    - admin
  APP-READERS:
    - readonly
`
	// Create temp file
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(configYAML)
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

func TestConfig_LoadFromYAMLReader_InvalidYAML(t *testing.T) {
	config := NewConfig()
	invalidYAML := `
rolePermissions:
  admin: [invalid yaml]
`
	reader := strings.NewReader(invalidYAML)

	err := config.LoadFromYAMLReader(reader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode YAML")
}

func TestConfig_LoadFromYAMLReader_ValidYAML(t *testing.T) {
	tests := []struct {
		name        string
		yamlInput   string
		wantErr     bool
		checkRoles  map[string]bool
		checkGroups map[string][]string
	}{
		{
			name: "valid config with admin role",
			yamlInput: `
rolePermissions:
  admin:
    - resource: app
      action: read
    - resource: app
      action: write
groupMappings:
  APP-ADMINS:
    - admin
`,
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
			yamlInput: `
rolePermissions:
  admin:
    - resource: system
      action: admin
  readonly:
    - resource: app
      action: read
groupMappings:
  ADMINS:
    - admin
  READERS:
    - readonly
`,
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
			yamlInput: `
rolePermissions: {}
groupMappings: {}
`,
			wantErr:     false,
			checkRoles:  map[string]bool{},
			checkGroups: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConfig()
			reader := strings.NewReader(tt.yamlInput)
			err := config.LoadFromYAMLReader(reader)

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

func TestConfig_FileExtensionDetection(t *testing.T) {
	// Test JSON extension detection
	jsonConfig := `{
		"rolePermissions": {
			"admin": [
				{"resource": "app", "action": "read"}
			]
		},
		"groupMappings": {
			"ADMINS": ["admin"]
		}
	}`

	yamlConfig := `
rolePermissions:
  admin:
    - resource: app
      action: read
groupMappings:
  ADMINS:
    - admin
`

	tests := []struct {
		name       string
		extension  string
		content    string
		wantErr    bool
		skipTest   bool
		skipReason string
	}{
		{
			name:      "JSON extension",
			extension: ".json",
			content:   jsonConfig,
			wantErr:   false,
		},
		{
			name:      "YAML extension",
			extension: ".yaml",
			content:   yamlConfig,
			wantErr:   false,
		},
		{
			name:      "YML extension",
			extension: ".yml",
			content:   yamlConfig,
			wantErr:   false,
		},
		{
			name:       "JSON content with YAML extension",
			extension:  ".yaml",
			content:    jsonConfig,
			wantErr:    false,
			skipTest:   false,
			skipReason: "YAML is a superset of JSON, so JSON content can be parsed as YAML",
		},
		{
			name:      "YAML content with JSON extension should error",
			extension: ".json",
			content:   yamlConfig,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTest {
				t.Skip(tt.skipReason)
			}

			// Create temp file with specific extension
			tmpFile, err := os.CreateTemp("", "config-*"+tt.extension)
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.content)
			require.NoError(t, err)
			tmpFile.Close()

			config := NewConfig()
			err = config.LoadFromFile(tmpFile.Name())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, config.RolePermissions, "admin")
				assert.Contains(t, config.GroupMappings, "ADMINS")
			}
		})
	}
}

// ============================================================================
// Role Permission Checks
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
// Group to Role Mapping
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
	assert.NotNil(t, config.UnitScopedRoles)
	assert.Empty(t, config.RolePermissions)
	assert.Empty(t, config.GroupMappings)
	assert.Empty(t, config.UnitScopedRoles)
}

func TestConfig_HasUnitScopedPermission(t *testing.T) {
	config := &Config{
		UnitScopedRoles: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
			},
			"admin": {
				{Resource: "app", Action: "delete"},
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
			name:       "app.creator has app:write",
			role:       "app.creator",
			permission: Permission{Resource: "app", Action: "write"},
			want:       true,
		},
		{
			name:       "app.creator does not have app:delete",
			role:       "app.creator",
			permission: Permission{Resource: "app", Action: "delete"},
			want:       false,
		},
		{
			name:       "admin has app:delete",
			role:       "admin",
			permission: Permission{Resource: "app", Action: "delete"},
			want:       true,
		},
		{
			name:       "unknown role returns false",
			role:       "unknown",
			permission: Permission{Resource: "app", Action: "read"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.HasUnitScopedPermission(tt.role, tt.permission)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_LoadFromJSON_WithUnitScopedRoles(t *testing.T) {
	jsonData := `{
		"groupMappings": {
			"TEST-GROUP": ["app.creator"]
		},
		"machineUnits": {},
		"unitScopedRoles": {
			"app.creator": [
				{"resource": "app", "action": "write"}
			]
		},
		"rolePermissions": {}
	}`

	config := NewConfig()
	err := config.LoadFromJSONReader(strings.NewReader(jsonData))
	assert.NoError(t, err)

	// Verify unit-scoped roles were loaded
	assert.Contains(t, config.UnitScopedRoles, "app.creator")
	assert.Len(t, config.UnitScopedRoles["app.creator"], 1)
	assert.True(t, config.HasUnitScopedPermission("app.creator", Permission{Resource: "app", Action: "write"}))
}

func TestConfig_LoadFromJSON_WithoutUnitScopedRoles_NoError(t *testing.T) {
	// Test backward compatibility - old config without unitScopedRoles
	jsonData := `{
		"groupMappings": {"TEST-GROUP": ["app.creator"]},
		"machineUnits": {},
		"rolePermissions": {}
	}`

	config := NewConfig()
	err := config.LoadFromJSONReader(strings.NewReader(jsonData))
	assert.NoError(t, err)
	assert.NotNil(t, config.UnitScopedRoles)
	assert.Empty(t, config.UnitScopedRoles)
}

func TestConfig_LoadFromYAML_WithUnitScopedRoles(t *testing.T) {
	yamlData := `
groupMappings:
  TEST-GROUP:
    - app.creator
machineUnits: {}
unitScopedRoles:
  app.creator:
    - resource: app
      action: write
rolePermissions: {}
`

	config := NewConfig()
	err := config.LoadFromYAMLReader(strings.NewReader(yamlData))
	assert.NoError(t, err)

	// Verify unit-scoped roles were loaded
	assert.Contains(t, config.UnitScopedRoles, "app.creator")
	assert.Len(t, config.UnitScopedRoles["app.creator"], 1)
	assert.True(t, config.HasUnitScopedPermission("app.creator", Permission{Resource: "app", Action: "write"}))
}

func TestConfig_GetDefaultConfig_HasUnitScopedRoles(t *testing.T) {
	config := GetDefaultConfig()

	// Verify UnitScopedRoles are populated
	assert.NotEmpty(t, config.UnitScopedRoles)
	assert.Contains(t, config.UnitScopedRoles, "unit.admin")
	assert.Contains(t, config.UnitScopedRoles, "app.creator")
	assert.Contains(t, config.UnitScopedRoles, "service.principal")

	// Check specific permissions
	assert.True(t, config.HasUnitScopedPermission("unit.admin", Permission{Resource: "app", Action: "manage"}))
	assert.True(t, config.HasUnitScopedPermission("app.creator", Permission{Resource: "app", Action: "write"}))
	assert.True(t, config.HasUnitScopedPermission("service.principal", Permission{Resource: "app", Action: "read"}))
}
