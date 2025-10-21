package authorization

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds authorization configuration
type Config struct {
	RolePermissions map[string][]Permission // Maps roles to the permissions they grant
	GroupMappings   map[string][]string     // Maps AD groups to internal roles
	MachineUnits    map[string][]string     // Maps client IDs to allowed unit IDs
	UnitScopedRoles map[string][]Permission // Maps roles to unit-scoped permissions
}

// NewConfig creates a new authorization config with defaults
func NewConfig() *Config {
	return &Config{
		RolePermissions: make(map[string][]Permission),
		GroupMappings:   make(map[string][]string),
		MachineUnits:    make(map[string][]string),
		UnitScopedRoles: make(map[string][]Permission),
	}
}

// LoadFromFile loads configuration from a JSON or YAML file based on file extension
func (c *Config) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// Detect file extension to determine parser
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".yaml" || ext == ".yml" {
		return c.LoadFromYAMLReader(file)
	}
	// Default to JSON for all other extensions
	return c.LoadFromJSONReader(file)
}

// LoadFromReader is kept for backward compatibility
// It defaults to JSON parsing
func (c *Config) LoadFromReader(r io.Reader) error {
	return c.LoadFromJSONReader(r)
}

// LoadFromJSONReader loads configuration from an io.Reader containing JSON data
func (c *Config) LoadFromJSONReader(r io.Reader) error {
	// Temporary structure for JSON parsing
	type jsonConfig struct {
		RolePermissions map[string][]struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		} `json:"rolePermissions"`
		GroupMappings   map[string][]string `json:"groupMappings"`
		MachineUnits    map[string][]string `json:"machineUnits"`
		UnitScopedRoles map[string][]struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		} `json:"unitScopedRoles"`
	}

	var jc jsonConfig
	if err := json.NewDecoder(r).Decode(&jc); err != nil {
		return fmt.Errorf("failed to decode JSON config: %w", err)
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
	c.MachineUnits = jc.MachineUnits // Store machine units

	// Parse unit-scoped roles
	c.UnitScopedRoles = make(map[string][]Permission)
	for role, perms := range jc.UnitScopedRoles {
		var permissions []Permission
		for _, p := range perms {
			permissions = append(permissions, Permission{
				Resource: p.Resource,
				Action:   p.Action,
			})
		}
		c.UnitScopedRoles[role] = permissions
	}

	return nil
}

// LoadFromYAMLReader loads configuration from an io.Reader containing YAML data
func (c *Config) LoadFromYAMLReader(r io.Reader) error {
	// Temporary structure for YAML parsing
	type yamlConfig struct {
		RolePermissions map[string][]struct {
			Resource string `yaml:"resource"`
			Action   string `yaml:"action"`
		} `yaml:"rolePermissions"`
		GroupMappings   map[string][]string `yaml:"groupMappings"`
		MachineUnits    map[string][]string `yaml:"machineUnits"` // Machine-to-unit mappings
		UnitScopedRoles map[string][]struct {
			Resource string `yaml:"resource"`
			Action   string `yaml:"action"`
		} `yaml:"unitScopedRoles"`
	}

	var yc yamlConfig

	// Read all content from reader
	content, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read YAML content: %w", err)
	}

	// Decode YAML
	if err := yaml.Unmarshal(content, &yc); err != nil {
		return fmt.Errorf("failed to decode YAML config: %w", err)
	}

	// Convert YAML permissions to Permission objects
	c.RolePermissions = make(map[string][]Permission)
	for role, perms := range yc.RolePermissions {
		var permissions []Permission
		for _, p := range perms {
			permissions = append(permissions, Permission{
				Resource: p.Resource,
				Action:   p.Action,
			})
		}
		c.RolePermissions[role] = permissions
	}

	c.GroupMappings = yc.GroupMappings
	c.MachineUnits = yc.MachineUnits

	// Parse unit-scoped roles
	c.UnitScopedRoles = make(map[string][]Permission)
	for role, perms := range yc.UnitScopedRoles {
		var permissions []Permission
		for _, p := range perms {
			permissions = append(permissions, Permission{
				Resource: p.Resource,
				Action:   p.Action,
			})
		}
		c.UnitScopedRoles[role] = permissions
	}

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
			"service.principal": {
				{Resource: "app", Action: "read"},
			},
		},
	}
}

// HasUnitScopedPermission checks if a role has unit-scoped permissions
// This is used when resources have a unitID to restrict access to users/machines
// that belong to the same unit AND have the appropriate role.
func (c *Config) HasUnitScopedPermission(role string, permission Permission) bool {
	permissions, exists := c.UnitScopedRoles[role]
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
