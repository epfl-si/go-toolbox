package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYAMLConfigLoading(t *testing.T) {
	// Create a new config
	config := NewConfig()

	// Load YAML config
	err := config.LoadFromFile("test_config.yaml")
	assert.NoError(t, err, "Loading YAML config should not produce an error")

	// Verify GroupMappings
	assert.Len(t, config.GroupMappings, 3, "Should have 3 group mappings")
	assert.Contains(t, config.GroupMappings, "APP-PORTAL-ADMINS-PROD", "Should contain admin group")
	assert.Contains(t, config.GroupMappings, "APP-PORTAL-READERS-PROD", "Should contain reader group")
	assert.Contains(t, config.GroupMappings, "APP-CREATORS-DEPT-A", "Should contain creator group")

	// Verify specific mapping
	adminRoles := config.GroupMappings["APP-PORTAL-ADMINS-PROD"]
	assert.Contains(t, adminRoles, "admin", "Admin group should map to admin role")

	// Verify RolePermissions
	assert.Len(t, config.RolePermissions, 3, "Should have 3 roles defined")
	assert.Contains(t, config.RolePermissions, "admin", "Should contain admin role")
	assert.Contains(t, config.RolePermissions, "readonly", "Should contain readonly role")
	assert.Contains(t, config.RolePermissions, "app.creator", "Should contain app.creator role")

	// Verify specific permissions
	adminPerms := config.RolePermissions["admin"]
	assert.Len(t, adminPerms, 8, "Admin role should have 8 permissions")

	readonlyPerms := config.RolePermissions["readonly"]
	assert.Len(t, readonlyPerms, 2, "Readonly role should have 2 permissions")

	// Verify permission checking functionality
	assert.True(t, config.HasRolePermission("admin", Permission{Resource: "system", Action: "admin"}),
		"Admin role should have system:admin permission")

	assert.True(t, config.HasRolePermission("readonly", Permission{Resource: "app", Action: "read"}),
		"Readonly role should have app:read permission")

	assert.False(t, config.HasRolePermission("readonly", Permission{Resource: "app", Action: "write"}),
		"Readonly role should NOT have app:write permission")

	// Test GetRolesForGroup
	assert.ElementsMatch(t, []string{"admin"}, config.GetRolesForGroup("APP-PORTAL-ADMINS-PROD"),
		"Should return correct roles for admin group")

	// Test GetRolesForGroups
	groups := []string{"APP-PORTAL-ADMINS-PROD", "APP-CREATORS-DEPT-A"}
	roles := config.GetRolesForGroups(groups)
	assert.Len(t, roles, 2, "Should have 2 unique roles")
	assert.Contains(t, roles, "admin", "Combined roles should contain admin")
	assert.Contains(t, roles, "app.creator", "Combined roles should contain app.creator")
}
