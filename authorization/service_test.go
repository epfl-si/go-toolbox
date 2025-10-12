package authorization

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// ============================================================================
// 6.1 Service Creation
// ============================================================================

func TestNewService_WithComponents(t *testing.T) {
	config := GetDefaultConfig()
	evaluator := NewPolicyEvaluator(config, nil)
	logger := zap.NewNop()
	authorizer := NewSimpleAuthorizer(evaluator, logger)

	service := NewService(authorizer, logger)

	assert.NotNil(t, service)
	assert.Equal(t, authorizer, service.authorizer)
	assert.Equal(t, logger, service.log)
}

func TestNewService_NilAuthorizer(t *testing.T) {
	service := NewService(nil, nil)

	assert.NotNil(t, service)
	assert.NotNil(t, service.authorizer)
	assert.NotNil(t, service.log)
}

// ============================================================================
// 6.2 Middleware Factory Methods
// ============================================================================

func TestService_RequirePermission(t *testing.T) {
	service := NewService(nil, nil)

	middleware := service.RequirePermission(Permission{Resource: "app", Action: "read"}, nil)

	assert.NotNil(t, middleware)
	assert.IsType(t, gin.HandlerFunc(nil), middleware)
}

func TestService_RequireRole(t *testing.T) {
	service := NewService(nil, nil)

	middleware := service.RequireRole("admin")

	assert.NotNil(t, middleware)
	assert.IsType(t, gin.HandlerFunc(nil), middleware)
}

func TestService_RequireAnyPermission(t *testing.T) {
	service := NewService(nil, nil)

	permissions := []Permission{
		{Resource: "app", Action: "read"},
		{Resource: "app", Action: "write"},
	}
	middleware := service.RequireAnyPermission(permissions, nil)

	assert.NotNil(t, middleware)
	assert.IsType(t, gin.HandlerFunc(nil), middleware)
}

func TestService_RequireAdmin(t *testing.T) {
	service := NewService(nil, nil)

	middleware := service.RequireAdmin()

	assert.NotNil(t, middleware)
	assert.IsType(t, gin.HandlerFunc(nil), middleware)
}

func TestService_RequireAppAccess(t *testing.T) {
	service := NewService(nil, nil)

	middleware := service.RequireAppAccess("write", nil)

	assert.NotNil(t, middleware)
	assert.IsType(t, gin.HandlerFunc(nil), middleware)
}

func TestService_RequireSystemAccess(t *testing.T) {
	service := NewService(nil, nil)

	middleware := service.RequireSystemAccess("admin")

	assert.NotNil(t, middleware)
	assert.IsType(t, gin.HandlerFunc(nil), middleware)
}

// ============================================================================
// 6.3 Direct Check Methods
// ============================================================================

func TestService_CanAccess(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)
	service := NewService(authorizer, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	resource := ResourceContext{}
	canAccess, err := service.CanAccess(c, Permission{Resource: "app", Action: "read"}, resource)

	assert.NoError(t, err)
	assert.True(t, canAccess)
}

func TestService_CanAccess_NoAuthContext(t *testing.T) {
	service := NewService(nil, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	// No auth context set
	resource := ResourceContext{}
	canAccess, err := service.CanAccess(c, Permission{Resource: "app", Action: "read"}, resource)

	assert.Error(t, err)
	assert.False(t, canAccess)
	assert.Contains(t, err.Error(), "failed to get auth context")
}

func TestService_CanAccessWithEnhancer(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)
	service := NewService(authorizer, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	enhancer := &testEnhancer{
		name: "TestEnhancer",
		enhanceFunc: func(ctx context.Context, resource ResourceContext) (ResourceContext, error) {
			result := resource.Clone()
			result["appID"] = "app-123"
			return result, nil
		},
	}

	canAccess, err := service.CanAccessWithEnhancer(c, Permission{Resource: "app", Action: "read"}, enhancer)

	assert.NoError(t, err)
	assert.True(t, canAccess)
}

func TestService_CanAccessWithEnhancer_EnhancerError(t *testing.T) {
	service := NewService(nil, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	enhancer := &testEnhancer{
		name: "ErrorEnhancer",
		enhanceFunc: func(ctx context.Context, resource ResourceContext) (ResourceContext, error) {
			return ResourceContext{}, errors.New("enhancement failed")
		},
	}

	canAccess, err := service.CanAccessWithEnhancer(c, Permission{Resource: "app", Action: "read"}, enhancer)

	assert.Error(t, err)
	assert.False(t, canAccess)
	assert.Contains(t, err.Error(), "failed to enhance resource")
}

func TestService_HasRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)
	service := NewService(authorizer, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	hasRole, err := service.HasRole(c, "admin")
	assert.NoError(t, err)
	assert.True(t, hasRole)

	hasRole, err = service.HasRole(c, "readonly")
	assert.NoError(t, err)
	assert.False(t, hasRole)
}

func TestService_CheckPermission(t *testing.T) {
	config := &Config{
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)
	service := NewService(authorizer, nil)

	machineCtx := &MachineAuthContext{
		ServicePrincipalID: "sp-1",
		Roles:              []string{"admin"},
	}

	authorized, err := service.CheckPermission(context.Background(), machineCtx, Permission{Resource: "app", Action: "write"}, ResourceContext{})
	assert.NoError(t, err)
	assert.True(t, authorized)
}

func TestService_CheckRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)
	service := NewService(authorizer, nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}

	hasRole := service.CheckRole(userCtx, "admin")
	assert.True(t, hasRole)
}

// ============================================================================
// 6.4 Context Information Methods
// ============================================================================

func TestService_GetUserRoles(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"GROUP-A": {"admin", "readonly"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)
	service := NewService(authorizer, nil)

	gin.SetMode(gin.TestMode)

	t.Run("user context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)

		userCtx := &UserAuthContext{
			UniqueID: "user-1",
			Groups:   []string{"GROUP-A"},
		}
		SetAuthContext(c, userCtx)

		roles, err := service.GetUserRoles(c)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"admin", "readonly"}, roles)
	})

	t.Run("machine context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)

		machineCtx := &MachineAuthContext{
			ServicePrincipalID: "sp-1",
			Roles:              []string{"service.principal"},
		}
		SetAuthContext(c, machineCtx)

		roles, err := service.GetUserRoles(c)
		assert.NoError(t, err)
		assert.Equal(t, []string{"service.principal"}, roles)
	})
}

func TestService_GetIdentifier(t *testing.T) {
	service := NewService(nil, nil)

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		authCtx AuthContext
		wantID  string
	}{
		{
			name: "user context",
			authCtx: &UserAuthContext{
				UniqueID: "user-123",
			},
			wantID: "user-123",
		},
		{
			name: "machine context",
			authCtx: &MachineAuthContext{
				ServicePrincipalID: "sp-456",
			},
			wantID: "sp-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest("GET", "/test", nil)
			SetAuthContext(c, tt.authCtx)

			identifier, err := service.GetIdentifier(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantID, identifier)
		})
	}
}

func TestService_IsUser(t *testing.T) {
	service := NewService(nil, nil)

	gin.SetMode(gin.TestMode)

	t.Run("user context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)

		userCtx := &UserAuthContext{UniqueID: "user-1"}
		SetAuthContext(c, userCtx)

		isUser, err := service.IsUser(c)
		assert.NoError(t, err)
		assert.True(t, isUser)
	})

	t.Run("machine context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)

		machineCtx := &MachineAuthContext{ServicePrincipalID: "sp-1"}
		SetAuthContext(c, machineCtx)

		isUser, err := service.IsUser(c)
		assert.NoError(t, err)
		assert.False(t, isUser)
	})
}

func TestService_IsMachine(t *testing.T) {
	service := NewService(nil, nil)

	gin.SetMode(gin.TestMode)

	t.Run("user context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)

		userCtx := &UserAuthContext{UniqueID: "user-1"}
		SetAuthContext(c, userCtx)

		isMachine, err := service.IsMachine(c)
		assert.NoError(t, err)
		assert.False(t, isMachine)
	})

	t.Run("machine context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)

		machineCtx := &MachineAuthContext{ServicePrincipalID: "sp-1"}
		SetAuthContext(c, machineCtx)

		isMachine, err := service.IsMachine(c)
		assert.NoError(t, err)
		assert.True(t, isMachine)
	})
}

func TestService_EnrichResourceContext(t *testing.T) {
	service := NewService(nil, nil)

	resource := ResourceContext{"appID": "app-123"}

	enriched, err := service.EnrichResourceContext(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, resource, enriched)
}

// ============================================================================
// Getter Methods
// ============================================================================

func TestService_GetAuthorizer(t *testing.T) {
	authorizer := NewSimpleAuthorizer(nil, nil)
	service := NewService(authorizer, nil)

	got := service.GetAuthorizer()
	assert.Equal(t, authorizer, got)
}

// ============================================================================
// Logging Tests
// ============================================================================

func TestService_LogAuthorizationAttempt(t *testing.T) {
	// This test mainly ensures the method doesn't panic
	service := NewService(nil, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	// Should not panic
	service.LogAuthorizationAttempt(c, Permission{Resource: "app", Action: "read"}, true, "test_reason")
}

func TestService_LogAuthorizationAttempt_NoAuthContext(t *testing.T) {
	service := NewService(nil, nil)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	// Should not panic even without auth context
	service.LogAuthorizationAttempt(c, Permission{Resource: "app", Action: "read"}, false, "no_auth")
}
