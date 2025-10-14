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

// Common permissions that can be used across applications
var (
	// Application permissions
	AppAdmin  = Permission{Resource: "app", Action: "admin"}
	AppCreate = Permission{Resource: "app", Action: "create"}
	AppDelete = Permission{Resource: "app", Action: "delete"}
	AppManage = Permission{Resource: "app", Action: "manage"}
	AppModify = Permission{Resource: "app", Action: "modify"}
	AppRead   = Permission{Resource: "app", Action: "read"}
	AppWrite  = Permission{Resource: "app", Action: "write"}

	// Secret permissions
	SecretRead  = Permission{Resource: "secret", Action: "read"}
	SecretWrite = Permission{Resource: "secret", Action: "write"}

	// System permissions
	SystemRead  = Permission{Resource: "system", Action: "read"}
	SystemAdmin = Permission{Resource: "system", Action: "admin"}

	// Unit permissions
	UnitRead  = Permission{Resource: "unit", Action: "read"}
	UnitWrite = Permission{Resource: "unit", Action: "write"}
)
