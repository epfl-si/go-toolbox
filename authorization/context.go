package authorization

import "context"

// AuthContext represents either a user or machine identity
type AuthContext interface {
	GetIdentifier() string // UniqueID for users, ServicePrincipalID for machines
	GetClientID() string
	GetGroups() []string // AD groups for users, app roles for machines
	GetUnits() []string  // Empty for machines
	IsUser() bool
	IsMachine() bool
	GetRoles() []string // Internal roles (derived from groups for users, direct for machines)
}

// UserAuthContext represents a human user's authentication context
type UserAuthContext struct {
	UniqueID string
	ClientID string
	Groups   []string // AD groups
	Units    []string // Organizational units
	Roles    []string // Derived internal roles
}

// GetIdentifier returns the user's unique ID
func (u *UserAuthContext) GetIdentifier() string {
	return u.UniqueID
}

// GetClientID returns the client ID (often empty for users)
func (u *UserAuthContext) GetClientID() string {
	return u.ClientID
}

// GetGroups returns the user's AD groups
func (u *UserAuthContext) GetGroups() []string {
	return u.Groups
}

// GetUnits returns the user's organizational units
func (u *UserAuthContext) GetUnits() []string {
	return u.Units
}

// IsUser returns true for user contexts
func (u *UserAuthContext) IsUser() bool {
	return true
}

// IsMachine returns false for user contexts
func (u *UserAuthContext) IsMachine() bool {
	return false
}

// GetRoles returns the user's internal roles (derived from groups)
func (u *UserAuthContext) GetRoles() []string {
	return u.Roles
}

// MachineAuthContext represents a machine/service principal's authentication context
type MachineAuthContext struct {
	ServicePrincipalID string
	ClientID           string
	Groups             []string // App roles for machines
	Roles              []string // Direct roles from token
}

// GetIdentifier returns the service principal ID
func (m *MachineAuthContext) GetIdentifier() string {
	return m.ServicePrincipalID
}

// GetClientID returns the client/application ID
func (m *MachineAuthContext) GetClientID() string {
	return m.ClientID
}

// GetGroups returns the machine's app roles (from Groups field)
func (m *MachineAuthContext) GetGroups() []string {
	return m.Groups
}

// GetUnits returns empty slice for machines
func (m *MachineAuthContext) GetUnits() []string {
	return []string{}
}

// IsUser returns false for machine contexts
func (m *MachineAuthContext) IsUser() bool {
	return false
}

// IsMachine returns true for machine contexts
func (m *MachineAuthContext) IsMachine() bool {
	return true
}

// GetRoles returns the machine's roles
func (m *MachineAuthContext) GetRoles() []string {
	return m.Roles
}

// ResourceContext contains information about the resource being accessed
type ResourceContext map[string]string

// Get retrieves a value from the resource context
func (r ResourceContext) Get(key string) string {
	return r[key]
}

// Set sets a value in the resource context
func (r ResourceContext) Set(key, value string) {
	r[key] = value
}

// Has checks if a key exists in the resource context
func (r ResourceContext) Has(key string) bool {
	_, ok := r[key]
	return ok
}

// Clone creates a copy of the resource context
func (r ResourceContext) Clone() ResourceContext {
	clone := make(ResourceContext)
	for k, v := range r {
		clone[k] = v
	}
	return clone
}

// ContextKey is the type for context keys
type ContextKey string

const (
	// AuthContextKey is the key for storing auth context in context
	AuthContextKey ContextKey = "auth_context"
	// ResourceContextKey is the key for storing resource context in context
	ResourceContextKey ContextKey = "resource_context"
)

// WithAuthContext adds an auth context to the context
func WithAuthContext(ctx context.Context, authCtx AuthContext) context.Context {
	return context.WithValue(ctx, AuthContextKey, authCtx)
}

// GetAuthContextFromCtx retrieves the auth context from context
func GetAuthContextFromCtx(ctx context.Context) (AuthContext, bool) {
	authCtx, ok := ctx.Value(AuthContextKey).(AuthContext)
	return authCtx, ok
}

// WithResourceContext adds a resource context to the context
func WithResourceContext(ctx context.Context, resourceCtx ResourceContext) context.Context {
	return context.WithValue(ctx, ResourceContextKey, resourceCtx)
}

// GetResourceContextFromCtx retrieves the resource context from context
func GetResourceContextFromCtx(ctx context.Context) (ResourceContext, bool) {
	resourceCtx, ok := ctx.Value(ResourceContextKey).(ResourceContext)
	return resourceCtx, ok
}
