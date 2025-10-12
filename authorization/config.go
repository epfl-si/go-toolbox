package authorization

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Config holds authorization configuration
type Config struct {
	RolePermissions map[string][]Permission // Maps roles to the permissions they grant
	GroupMappings   map[string][]string     // Maps AD groups to internal roles
}

// NewConfig creates a new authorization config with defaults
func NewConfig() *Config {
	return &Config{
		RolePermissions: make(map[string][]Permission),
		GroupMappings:   make(map[string][]string),
	}
}

// LoadFromFile loads configuration from a JSON file
func (c *Config) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	return c.LoadFromReader(file)
}

// LoadFromReader loads configuration from an io.Reader
func (c *Config) LoadFromReader(r io.Reader) error {
	// Temporary structure for JSON parsing
	type jsonConfig struct {
		RolePermissions map[string][]struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		} `json:"rolePermissions"`
		GroupMappings map[string][]string `json:"groupMappings"`
	}

	var jc jsonConfig
	if err := json.NewDecoder(r).Decode(&jc); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	// Convert JSON permissions to Permission objects
	c.RolePermissions = make(map[string][]Permission)
	for role, perms := range jc.RolePermissions {
		var permissions []Permission
		for _, p := range perms {
			permissions = append(permissions, Permission{
				Resource: p.Resource,
				Action:   p.Action,
			})
		}
		c.RolePermissions[role] = permissions
	}

	c.GroupMappings = jc.GroupMappings
	return nil
}

// GetDefaultConfig returns a default configuration for development/testing
func GetDefaultConfig() *Config {
	return &Config{
		GroupMappings: map[string][]string{
			// Admin groups
			"APP-PORTAL-ADMINS-PROD": {"admin"},
			"APP-PORTAL-ADMINS-DEV":  {"admin"},

			// Read-only groups
			"APP-PORTAL-READERS-PROD": {"readonly"},
			"APP-PORTAL-READERS-DEV":  {"readonly"},

			// Application creator groups (example departments)
			"APP-CREATORS-DEPT-A": {"app.creator", "app.reader"},
			"APP-CREATORS-DEPT-B": {"app.creator", "app.reader"},

			// Service principal groups
			"SERVICE-PRINCIPALS-PROD": {"service.principal"},
			"SERVICE-PRINCIPALS-DEV":  {"service.principal"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				// Full access to all resources
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "app", Action: "delete"},
				{Resource: "app", Action: "admin"},
				{Resource: "unit", Action: "read"},
				{Resource: "unit", Action: "write"},
				{Resource: "unit", Action: "admin"},
				{Resource: "secret", Action: "read"},
				{Resource: "secret", Action: "write"},
				{Resource: "system", Action: "read"},
				{Resource: "system", Action: "write"},
				{Resource: "system", Action: "admin"},
			},
			"readonly": {
				// Read-only access to most resources
				{Resource: "app", Action: "read"},
				{Resource: "unit", Action: "read"},
				{Resource: "system", Action: "read"},
			},
			"app.creator": {
				// Can create and modify applications
				{Resource: "app", Action: "write"},
				{Resource: "secret", Action: "write"},
			},
			"app.reader": {
				// Can read application information
				{Resource: "app", Action: "read"},
				{Resource: "unit", Action: "read"},
			},
			"service.principal": {
				// Machine-to-machine access
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "secret", Action: "read"},
			},
		},
	}
}

// HasRolePermission checks if a role has a specific permission
func (c *Config) HasRolePermission(role string, permission Permission) bool {
	permissions, exists := c.RolePermissions[role]
	if !exists {
		return false
	}

	for _, p := range permissions {
		if p.Equals(permission) {
			return true
		}
	}
	return false
}

// GetRolesForGroup returns the roles associated with a group
func (c *Config) GetRolesForGroup(group string) []string {
	return c.GroupMappings[group]
}

// GetRolesForGroups returns all unique roles for a set of groups
func (c *Config) GetRolesForGroups(groups []string) []string {
	roleSet := make(map[string]bool)

	for _, group := range groups {
		if roles, ok := c.GroupMappings[group]; ok {
			for _, role := range roles {
				roleSet[role] = true
			}
		}
	}

	// Convert set to slice
	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}

	return roles
}
