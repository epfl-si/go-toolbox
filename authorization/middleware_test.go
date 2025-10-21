package authorization

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ============================================================================
// 7.1 RequirePermission Middleware Tests
// ============================================================================

func TestMiddleware_RequirePermission_Authorized(t *testing.T) {
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

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	middleware := RequirePermission(Permission{Resource: "app", Action: "read"}, nil, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify request proceeded (no abort)
	assert.False(t, c.IsAborted())
}

func TestMiddleware_RequirePermission_Denied(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{
			"readonly": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"READERS"},
	}
	SetAuthContext(c, userCtx)

	middleware := RequirePermission(Permission{Resource: "app", Action: "write"}, nil, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify response is 403 Forbidden
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Insufficient permissions")
}

func TestMiddleware_RequirePermission_NoAuthContext(t *testing.T) {
	authorizer := NewSimpleAuthorizer(nil, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	// No auth context set
	middleware := RequirePermission(Permission{Resource: "app", Action: "read"}, nil, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify response is 401 Unauthorized
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authentication required")
}

func TestMiddleware_RequirePermission_WithExtractor(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"APP-CREATORS": {"app.creator"},
		},
		RolePermissions: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "write"},
			},
		},
		UnitScopedRoles: map[string][]Permission{
			"app.creator": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
				{Resource: "secret", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/apps/123", nil)
	c.Params = gin.Params{{Key: "id", Value: "123"}}

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"APP-CREATORS"},
		Units:    []string{"unit-123"},
	}
	SetAuthContext(c, userCtx)

	enhancer := &testEnhancer{
		name: "TestEnhancer",
		enhanceFunc: func(ctx context.Context, resource ResourceContext) (ResourceContext, error) {
			ginCtx, _ := GetGinContext(ctx)
			result := resource.Clone()
			result["appID"] = ginCtx.Param("id")
			result["unitID"] = "unit-123"
			return result, nil
		},
	}

	middleware := RequirePermission(Permission{Resource: "app", Action: "write"}, enhancer, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify request proceeded
	assert.False(t, c.IsAborted())

	// Verify resource context was stored
	resCtx, exists := GetResourceContext(c)
	assert.True(t, exists)
	assert.Equal(t, "123", resCtx["appID"])
}

func TestMiddleware_RequirePermission_ExtractorError(t *testing.T) {
	authorizer := NewSimpleAuthorizer(nil, nil)

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
			return ResourceContext{}, errors.New("extraction failed")
		},
	}

	middleware := RequirePermission(Permission{Resource: "app", Action: "read"}, enhancer, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify response is 400 Bad Request
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request")
}

func TestMiddleware_RequirePermission_AuthorizerError(t *testing.T) {
	// Create a mock authorizer that returns an error
	mockAuthorizer := &mockErrorAuthorizer{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	middleware := RequirePermission(Permission{Resource: "app", Action: "read"}, nil, mockAuthorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify response is 500 Internal Server Error
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization check failed")
}

func TestMiddleware_RequirePermission_StoresResourceContext(t *testing.T) {
	config := GetDefaultConfig()
	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "admin-user",
		Groups:   []string{"APP-PORTAL-ADMINS-PROD"},
	}
	SetAuthContext(c, userCtx)

	enhancer := &testEnhancer{
		name: "TestEnhancer",
		enhanceFunc: func(ctx context.Context, resource ResourceContext) (ResourceContext, error) {
			result := resource.Clone()
			result["appID"] = "app-123"
			result["unitID"] = "unit-456"
			return result, nil
		},
	}

	middleware := RequirePermission(Permission{Resource: "app", Action: "read"}, enhancer, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify resource context was stored
	resCtx, exists := GetResourceContext(c)
	assert.True(t, exists)
	assert.Equal(t, "app-123", resCtx["appID"])
	assert.Equal(t, "unit-456", resCtx["unitID"])
}

// ============================================================================
// 7.2 RequireRole Middleware Tests
// ============================================================================

func TestMiddleware_RequireRole_HasRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	middleware := RequireRole("admin", authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify request proceeded
	assert.False(t, c.IsAborted())
}

func TestMiddleware_RequireRole_NoRole(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"READERS"},
	}
	SetAuthContext(c, userCtx)

	middleware := RequireRole("admin", authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify response is 403 Forbidden
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Insufficient permissions")
}

func TestMiddleware_RequireRole_NoAuthContext(t *testing.T) {
	authorizer := NewSimpleAuthorizer(nil, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	middleware := RequireRole("admin", authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify response is 401 Unauthorized
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ============================================================================
// 7.3 RequireAnyPermission Middleware Tests
// ============================================================================

func TestMiddleware_RequireAnyPermission_FirstMatches(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"ADMINS": {"admin"},
		},
		RolePermissions: map[string][]Permission{
			"admin": {
				{Resource: "app", Action: "read"},
				{Resource: "app", Action: "write"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	permissions := []Permission{
		{Resource: "app", Action: "read"},
		{Resource: "app", Action: "write"},
	}

	middleware := RequireAnyPermission(permissions, nil, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify request proceeded
	assert.False(t, c.IsAborted())
}

func TestMiddleware_RequireAnyPermission_SecondMatches(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{
			"readonly": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"READERS"},
	}
	SetAuthContext(c, userCtx)

	permissions := []Permission{
		{Resource: "app", Action: "write"},
		{Resource: "app", Action: "read"},
	}

	middleware := RequireAnyPermission(permissions, nil, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify request proceeded (second permission matched)
	assert.False(t, c.IsAborted())
}

func TestMiddleware_RequireAnyPermission_NoneMatch(t *testing.T) {
	config := &Config{
		GroupMappings: map[string][]string{
			"READERS": {"readonly"},
		},
		RolePermissions: map[string][]Permission{
			"readonly": {
				{Resource: "app", Action: "read"},
			},
		},
	}

	evaluator := NewPolicyEvaluator(config, nil)
	authorizer := NewSimpleAuthorizer(evaluator, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"READERS"},
	}
	SetAuthContext(c, userCtx)

	permissions := []Permission{
		{Resource: "app", Action: "write"},
		{Resource: "app", Action: "delete"},
	}

	middleware := RequireAnyPermission(permissions, nil, authorizer, nil)

	// Execute middleware
	middleware(c)

	// Verify response is 403 Forbidden
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Insufficient permissions")
}

func TestMiddleware_RequireAnyPermission_AuthorizerError(t *testing.T) {
	mockAuthorizer := &mockErrorAuthorizer{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
		Groups:   []string{"ADMINS"},
	}
	SetAuthContext(c, userCtx)

	permissions := []Permission{
		{Resource: "app", Action: "read"},
	}

	middleware := RequireAnyPermission(permissions, nil, mockAuthorizer, nil)

	// Execute middleware
	middleware(c)

	// Should continue to next permission (errors don't fail fast)
	// Since all fail, should get 403
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ============================================================================
// 7.4 Context Helper Tests
// ============================================================================

func TestGetAuthContext_FromGinKey(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
	}

	// Set using our helper
	SetAuthContext(c, userCtx)

	// Retrieve
	retrieved, err := GetAuthContext(c)
	assert.NoError(t, err)
	assert.Equal(t, userCtx, retrieved)
}

func TestGetAuthContext_FromRequestContext(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
	}

	// Set in request context only
	ctx := WithAuthContext(context.Background(), userCtx)
	c.Request, _ = http.NewRequestWithContext(ctx, "GET", "/test", nil)

	// Should retrieve from request context
	retrieved, err := GetAuthContext(c)
	assert.NoError(t, err)
	assert.Equal(t, userCtx, retrieved)
}

func TestGetAuthContext_NotFound(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	// No auth context set
	retrieved, err := GetAuthContext(c)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "no authentication context found")
}

func TestSetAuthContext(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test", nil)

	userCtx := &UserAuthContext{
		UniqueID: "user-1",
	}

	SetAuthContext(c, userCtx)

	// Verify it's set in Gin context
	val, exists := c.Get(string(AuthContextKey))
	assert.True(t, exists)
	assert.Equal(t, userCtx, val)

	// Verify it's also in request context
	retrieved, ok := GetAuthContextFromCtx(c.Request.Context())
	assert.True(t, ok)
	assert.Equal(t, userCtx, retrieved)
}

func TestGetResourceContext(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	resource := ResourceContext{
		"appID":  "app-123",
		"unitID": "unit-456",
	}

	// Set resource context
	c.Set(string(ResourceContextKey), resource)

	// Retrieve
	retrieved, exists := GetResourceContext(c)
	assert.True(t, exists)
	assert.Equal(t, resource, retrieved)
}

func TestGetResourceContext_NotFound(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// No resource context set
	retrieved, exists := GetResourceContext(c)
	assert.False(t, exists)
	assert.Nil(t, retrieved)
}

// ============================================================================
// Mock Authorizer for Error Testing
// ============================================================================

type mockErrorAuthorizer struct{}

func (m *mockErrorAuthorizer) HasRole(authCtx AuthContext, role string) bool {
	return false
}

func (m *mockErrorAuthorizer) HasPermission(ctx context.Context, authCtx AuthContext, permission Permission, resource ResourceContext) (bool, error) {
	return false, errors.New("mock authorizer error")
}

// Test enhancer for tests
type testEnhancer struct {
	name        string
	enhanceFunc func(ctx context.Context, resource ResourceContext) (ResourceContext, error)
}

func (e *testEnhancer) Enhance(ctx context.Context, resource ResourceContext) (ResourceContext, error) {
	return e.enhanceFunc(ctx, resource)
}

func (e *testEnhancer) Name() string {
	return e.name
}
