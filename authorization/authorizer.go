// Package authorization abstract the authorization away in an independant loosely coupled module
package authorization

import (
	"context"

	"go.uber.org/zap"
)

// Authorizer is the base interface for all authorization operations
type Authorizer interface {
	// HasRole checks if the auth context has a specific role
	HasRole(authCtx AuthContext, role string) bool

	// HasPermission checks if the auth context has a specific permission for a resource
	HasPermission(ctx context.Context, authCtx AuthContext, permission Permission, resource ResourceContext) (bool, error)
}

// SimpleAuthorizer provides a concrete implementation of Authorizer
type SimpleAuthorizer struct {
	evaluator *PolicyEvaluator
	log       *zap.Logger
}

// NewSimpleAuthorizer creates a new simple authorizer
func NewSimpleAuthorizer(evaluator *PolicyEvaluator, log *zap.Logger) *SimpleAuthorizer {
	if evaluator == nil {
		evaluator = NewPolicyEvaluator(nil, log)
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &SimpleAuthorizer{
		evaluator: evaluator,
		log:       log,
	}
}

// HasRole checks if the auth context has a specific role
func (a *SimpleAuthorizer) HasRole(authCtx AuthContext, role string) bool {
	// Get all roles for the auth context
	var roles []string

	if authCtx.IsMachine() {
		// For machines, check direct roles
		roles = authCtx.GetRoles()
	} else {
		// For users, get roles from group mappings
		roles = a.evaluator.config.GetRolesForGroups(authCtx.GetGroups())
	}

	// Check if the requested role is present
	for _, r := range roles {
		if r == role {
			a.log.Debug("Role check passed",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("role", role),
				zap.Bool("is_user", authCtx.IsUser()),
			)
			return true
		}
	}

	a.log.Debug("Role check failed",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.String("role", role),
		zap.Strings("available_roles", roles),
	)
	return false
}

// HasPermission checks if the auth context has a specific permission for a resource
func (a *SimpleAuthorizer) HasPermission(ctx context.Context, authCtx AuthContext, permission Permission, resource ResourceContext) (bool, error) {
	// Evaluate the permission
	authorized, reason := a.evaluator.Evaluate(authCtx, permission, resource)

	// Log the decision
	a.log.Debug("Authorization decision",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.String("permission", permission.String()),
		zap.Bool("authorized", authorized),
		zap.String("reason", reason),
		zap.Bool("is_user", authCtx.IsUser()),
		zap.Bool("is_machine", authCtx.IsMachine()),
	)

	return authorized, nil
}

// AuthorizerBuilder helps build an Authorizer with fluent interface
type AuthorizerBuilder struct {
	config *Config
	log    *zap.Logger
}

// NewAuthorizerBuilder creates a new authorizer builder
func NewAuthorizerBuilder() *AuthorizerBuilder {
	return &AuthorizerBuilder{}
}

// WithConfig sets the configuration
func (b *AuthorizerBuilder) WithConfig(config *Config) *AuthorizerBuilder {
	b.config = config
	return b
}

// WithLogger sets the logger
func (b *AuthorizerBuilder) WithLogger(log *zap.Logger) *AuthorizerBuilder {
	b.log = log
	return b
}

// Build creates the authorizer
func (b *AuthorizerBuilder) Build() *SimpleAuthorizer {
	evaluator := NewPolicyEvaluator(b.config, b.log)
	return NewSimpleAuthorizer(evaluator, b.log)
}
