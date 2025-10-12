package authorization_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/epfl-si/go-toolbox/authorization"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithGinContext tests the gin context storage and retrieval
func TestWithGinContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(w)

	// Test adding gin context
	ctx := authorization.WithGinContext(context.Background(), ginCtx)
	require.NotNil(t, ctx)

	// Test retrieving gin context
	retrieved, ok := authorization.GetGinContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, ginCtx, retrieved)

	// Test with context that doesn't have gin context
	emptyCtx := context.Background()
	retrieved, ok = authorization.GetGinContext(emptyCtx)
	assert.False(t, ok)
	assert.Nil(t, retrieved)
}

// MockEnhancer is a simple implementation of ResourceEnhancer for testing
type MockEnhancer struct {
	EnhanceFunc func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error)
	NameValue   string
}

func (m *MockEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	if m.EnhanceFunc != nil {
		return m.EnhanceFunc(ctx, resource)
	}
	return resource, nil
}

func (m *MockEnhancer) Name() string {
	if m.NameValue != "" {
		return m.NameValue
	}
	return "MockEnhancer"
}

// TestResourceEnhancer tests the ResourceEnhancer interface
func TestResourceEnhancer(t *testing.T) {
	tests := []struct {
		name     string
		enhancer *MockEnhancer
		input    authorization.ResourceContext
		expected authorization.ResourceContext
		wantErr  bool
	}{
		{
			name: "successful enhancement",
			enhancer: &MockEnhancer{
				EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
					result := resource.Clone()
					result["enhanced"] = "true"
					return result, nil
				},
				NameValue: "TestEnhancer",
			},
			input:    authorization.ResourceContext{"original": "data"},
			expected: authorization.ResourceContext{"original": "data", "enhanced": "true"},
			wantErr:  false,
		},
		{
			name: "no changes",
			enhancer: &MockEnhancer{
				EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
					return resource, nil
				},
			},
			input:    authorization.ResourceContext{"test": "value"},
			expected: authorization.ResourceContext{"test": "value"},
			wantErr:  false,
		},
		{
			name: "enhancement error",
			enhancer: &MockEnhancer{
				EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
					return nil, assert.AnError
				},
			},
			input:    authorization.ResourceContext{"test": "data"},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.enhancer.Enhance(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}

			// Test Name() method
			if tt.enhancer.NameValue != "" {
				assert.Equal(t, tt.enhancer.NameValue, tt.enhancer.Name())
			} else {
				assert.Equal(t, "MockEnhancer", tt.enhancer.Name())
			}
		})
	}
}
