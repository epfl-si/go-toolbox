package authorization

import "fmt"

// Permission represents a required permission with resource and action
type Permission struct {
	Resource string // "app", "unit", "secret", "system", etc.
	Action   string // "read", "write", "delete", "admin"
}

// String returns a string representation of the permission
func (p Permission) String() string {
	return fmt.Sprintf("%s:%s", p.Resource, p.Action)
}

// Equals checks if two permissions are equal
func (p Permission) Equals(other Permission) bool {
	return p.Resource == other.Resource && p.Action == other.Action
}

// Common permissions that can be used across the application
var (
	// Application permissions
	AppCreate = Permission{Resource: "app", Action: "create"}
	AppRead   = Permission{Resource: "app", Action: "read"}
	AppModify = Permission{Resource: "app", Action: "modify"}
	AppDelete = Permission{Resource: "app", Action: "delete"}
	AppAdmin  = Permission{Resource: "app", Action: "admin"}
)
