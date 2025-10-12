package authorization

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Service provides high-level authorization utilities and middleware creation
type Service struct {
	authorizer *SimpleAuthorizer
	log        *zap.Logger
}

// NewService creates a new authorization service
func NewService(authorizer *SimpleAuthorizer, log *zap.Logger) *Service {
	if authorizer == nil {
		authorizer = NewSimpleAuthorizer(nil, log)
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &Service{
		authorizer: authorizer,
		log:        log,
	}
}

// RequirePermission creates a middleware that requires a specific permission
func (s *Service) RequirePermission(permission Permission, enhancer ResourceEnhancer) gin.HandlerFunc {
	return RequirePermission(permission, enhancer, s.authorizer, s.log)
}

// RequireRole creates a middleware that requires a specific role
func (s *Service) RequireRole(role string) gin.HandlerFunc {
	return RequireRole(role, s.authorizer, s.log)
}

// RequireAnyPermission creates a middleware that requires at least one of the specified permissions
func (s *Service) RequireAnyPermission(permissions []Permission, enhancer ResourceEnhancer) gin.HandlerFunc {
	return RequireAnyPermission(permissions, enhancer, s.authorizer, s.log)
}

// CanAccess checks if the current auth context can access a resource with given permission
func (s *Service) CanAccess(c *gin.Context, permission Permission, resource ResourceContext) (bool, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false, fmt.Errorf("failed to get auth context: %w", err)
	}

	return s.authorizer.HasPermission(c.Request.Context(), authCtx, permission, resource)
}

// CanAccessWithEnhancer checks if the current auth context can access a resource
func (s *Service) CanAccessWithEnhancer(c *gin.Context, permission Permission, enhancer ResourceEnhancer) (bool, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false, fmt.Errorf("failed to get auth context: %w", err)
	}

	resource := make(ResourceContext)
	if enhancer != nil {
		ctx := WithGinContext(c.Request.Context(), c)
		ctx = WithAuthContext(ctx, authCtx)

		enhanced, err := enhancer.Enhance(ctx, resource)
		if err != nil {
			return false, fmt.Errorf("failed to enhance resource: %w", err)
		}
		resource = enhanced
	}

	return s.authorizer.HasPermission(c.Request.Context(), authCtx, permission, resource)
}

// HasRole checks if the current auth context has a specific role
func (s *Service) HasRole(c *gin.Context, role string) (bool, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false, fmt.Errorf("failed to get auth context: %w", err)
	}

	return s.authorizer.HasRole(authCtx, role), nil
}

// GetUserRoles returns the roles for the current user context
func (s *Service) GetUserRoles(c *gin.Context) ([]string, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth context: %w", err)
	}

	if authCtx.IsUser() {
		return s.authorizer.evaluator.config.GetRolesForGroups(authCtx.GetGroups()), nil
	}

	return authCtx.GetRoles(), nil
}

// GetIdentifier returns the identifier of the current auth context
func (s *Service) GetIdentifier(c *gin.Context) (string, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return "", fmt.Errorf("failed to get auth context: %w", err)
	}

	return authCtx.GetIdentifier(), nil
}

// IsUser checks if the current auth context is a user
func (s *Service) IsUser(c *gin.Context) (bool, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false, fmt.Errorf("failed to get auth context: %w", err)
	}

	return authCtx.IsUser(), nil
}

// IsMachine checks if the current auth context is a machine
func (s *Service) IsMachine(c *gin.Context) (bool, error) {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false, fmt.Errorf("failed to get auth context: %w", err)
	}

	return authCtx.IsMachine(), nil
}

// CheckPermission is a utility method to check a permission without middleware
func (s *Service) CheckPermission(ctx context.Context, authCtx AuthContext, permission Permission, resource ResourceContext) (bool, error) {
	return s.authorizer.HasPermission(ctx, authCtx, permission, resource)
}

// CheckRole is a utility method to check a role without middleware
func (s *Service) CheckRole(authCtx AuthContext, role string) bool {
	return s.authorizer.HasRole(authCtx, role)
}

// EnrichResourceContext is deprecated and now returns the resource unchanged
// Use ResourceEnhancer directly instead
// DEPRECATED: Use ResourceEnhancer directly
func (s *Service) EnrichResourceContext(ctx context.Context, resource ResourceContext) (ResourceContext, error) {
	return resource, nil
}

// RequireAdmin creates a middleware that requires admin role
func (s *Service) RequireAdmin() gin.HandlerFunc {
	return s.RequireRole("admin")
}

// RequireReadOnly creates a middleware that requires at least readonly permissions
func (s *Service) RequireReadOnly() gin.HandlerFunc {
	return s.RequireAnyPermission([]Permission{
		{Resource: "system", Action: "read"},
		{Resource: "app", Action: "read"},
	}, nil)
}

// RequireAppAccess creates a middleware for app-specific access
func (s *Service) RequireAppAccess(action string, enhancer ResourceEnhancer) gin.HandlerFunc {
	return s.RequirePermission(Permission{Resource: "app", Action: action}, enhancer)
}

// RequireUnitAccess creates a middleware for unit-specific access
func (s *Service) RequireUnitAccess(action string, enhancer ResourceEnhancer) gin.HandlerFunc {
	return s.RequirePermission(Permission{Resource: "unit", Action: action}, enhancer)
}

// RequireSystemAccess creates a middleware for system-level access
func (s *Service) RequireSystemAccess(action string) gin.HandlerFunc {
	return s.RequirePermission(Permission{Resource: "system", Action: action}, nil)
}

// LogAuthorizationAttempt logs an authorization attempt with context
func (s *Service) LogAuthorizationAttempt(c *gin.Context, permission Permission, authorized bool, reason string) {
	authCtx, _ := GetAuthContext(c)
	identifier := "unknown"
	isUser := false
	isMachine := false

	if authCtx != nil {
		identifier = authCtx.GetIdentifier()
		isUser = authCtx.IsUser()
		isMachine = authCtx.IsMachine()
	}

	s.log.Info("Authorization attempt",
		zap.String("identifier", identifier),
		zap.String("permission", permission.String()),
		zap.Bool("authorized", authorized),
		zap.String("reason", reason),
		zap.String("path", c.Request.URL.Path),
		zap.String("method", c.Request.Method),
		zap.Bool("is_user", isUser),
		zap.Bool("is_machine", isMachine),
	)
}

// GetAuthorizer returns the underlying authorizer
func (s *Service) GetAuthorizer() *SimpleAuthorizer {
	return s.authorizer
}
