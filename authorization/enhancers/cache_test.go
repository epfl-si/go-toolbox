package enhancers_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/epfl-si/go-toolbox/authorization"
	"github.com/epfl-si/go-toolbox/authorization/enhancers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockEnhancer is a simple implementation of ResourceEnhancer for testing
type MockEnhancer struct {
	EnhanceFunc func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error)
	NameValue   string
	CallCount   int
}

func (m *MockEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	m.CallCount++
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

func TestNewCacheEnhancer(t *testing.T) {
	// Test with nil inner enhancer
	_, err := enhancers.NewCacheEnhancer(nil, 5*time.Minute)
	assert.Error(t, err, "Should return error with nil inner enhancer")

	// Test with valid inner enhancer
	mock := &MockEnhancer{}
	cache, err := enhancers.NewCacheEnhancer(mock, 5*time.Minute)
	assert.NoError(t, err)
	assert.NotNil(t, cache)
	assert.Contains(t, cache.Name(), "Cache")
	assert.Contains(t, cache.Name(), mock.Name())
}

func TestCacheEnhancerWithLogger(t *testing.T) {
	mock := &MockEnhancer{}
	logger := zap.NewNop()

	cache, err := enhancers.NewCacheEnhancerWithLogger(mock, 5*time.Minute, logger)
	assert.NoError(t, err)
	assert.NotNil(t, cache)
}

func TestCacheEnhancerHitMiss(t *testing.T) {
	callCount := 0
	mock := &MockEnhancer{
		NameValue: "TestEnhancer",
		EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			callCount++
			result := resource.Clone()
			result["enhanced"] = "true"
			result["count"] = strconv.Itoa(callCount)
			return result, nil
		},
	}

	cache, err := enhancers.NewCacheEnhancer(mock, 5*time.Minute)
	require.NoError(t, err)

	// First call - should be a cache miss
	resource := authorization.ResourceContext{"key": "value"}
	result1, err := cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, "true", result1["enhanced"])
	assert.Equal(t, "1", result1["count"])
	assert.Equal(t, 1, mock.CallCount)

	// Second call with same resource - should be a cache hit
	result2, err := cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, "true", result2["enhanced"])
	assert.Equal(t, "1", result2["count"]) // Count should not increase
	assert.Equal(t, 1, mock.CallCount)     // Inner enhancer should not be called again

	// Call with different resource - should be a cache miss
	differentResource := authorization.ResourceContext{"key": "different"}
	result3, err := cache.Enhance(context.Background(), differentResource)
	assert.NoError(t, err)
	assert.Equal(t, "true", result3["enhanced"])
	assert.Equal(t, "2", result3["count"])
	assert.Equal(t, 2, mock.CallCount) // Inner enhancer should be called again
}

func TestCacheEnhancerKeyGeneration(t *testing.T) {
	mock := &MockEnhancer{
		EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["enhanced"] = "true"
			return result, nil
		},
	}

	cache, err := enhancers.NewCacheEnhancer(mock, 5*time.Minute)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		resource authorization.ResourceContext
	}{
		{
			name:     "appID based key",
			resource: authorization.ResourceContext{"appID": "app123"},
		},
		{
			name:     "configID based key",
			resource: authorization.ResourceContext{"configID": "cfg456"},
		},
		{
			name:     "unitID based key",
			resource: authorization.ResourceContext{"unitID": "unit789"},
		},
		{
			name:     "id based key",
			resource: authorization.ResourceContext{"id": "12345"},
		},
		{
			name:     "complex resource",
			resource: authorization.ResourceContext{"complex": "value", "nested": "nested_value"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// First call - should miss
			result1, err := cache.Enhance(context.Background(), tc.resource)
			assert.NoError(t, err)
			assert.Equal(t, "true", result1["enhanced"])

			// Reset call count
			mock.CallCount = 0

			// Second call - should hit
			result2, err := cache.Enhance(context.Background(), tc.resource)
			assert.NoError(t, err)
			assert.Equal(t, "true", result2["enhanced"])
			assert.Equal(t, 0, mock.CallCount, "Inner enhancer should not be called on cache hit")
		})
	}
}

func TestCacheEnhancerTTL(t *testing.T) {
	mock := &MockEnhancer{
		EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["enhanced"] = "true"
			return result, nil
		},
	}

	// Create cache with very short TTL
	shortTTL := 50 * time.Millisecond
	cache, err := enhancers.NewCacheEnhancer(mock, shortTTL)
	require.NoError(t, err)

	resource := authorization.ResourceContext{"key": "value"}

	// First call - should miss
	_, err = cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, 1, mock.CallCount)

	// Second call immediately - should hit
	_, err = cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, 1, mock.CallCount, "Should not call inner enhancer on cache hit")

	// Wait for TTL to expire
	time.Sleep(shortTTL * 2)

	// Call after TTL expired - should miss
	_, err = cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, 2, mock.CallCount, "Should call inner enhancer after TTL expired")
}

func TestCacheEnhancerErrorHandling(t *testing.T) {
	errorOnFirstCall := true
	mock := &MockEnhancer{
		EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			if errorOnFirstCall {
				errorOnFirstCall = false
				return nil, assert.AnError
			}
			result := resource.Clone()
			result["enhanced"] = "true"
			return result, nil
		},
	}

	cache, err := enhancers.NewCacheEnhancer(mock, 5*time.Minute)
	require.NoError(t, err)

	resource := authorization.ResourceContext{"key": "value"}

	// First call - should error
	result1, err := cache.Enhance(context.Background(), resource)
	assert.Error(t, err)
	assert.Equal(t, resource, result1, "Should return original resource on error")

	// Second call - should succeed and not be cached
	result2, err := cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, "true", result2["enhanced"])
}

func TestCacheEnhancerClear(t *testing.T) {
	mock := &MockEnhancer{
		EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["enhanced"] = "true"
			return result, nil
		},
	}

	cache, err := enhancers.NewCacheEnhancer(mock, 5*time.Minute)
	require.NoError(t, err)

	resource := authorization.ResourceContext{"key": "value"}

	// First call - should miss
	_, err = cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, 1, mock.CallCount)

	// Second call - should hit
	_, err = cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, 1, mock.CallCount)

	// Clear cache
	cache.Clear()

	// Call after clear - should miss
	_, err = cache.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Equal(t, 2, mock.CallCount, "Should call inner enhancer after cache clear")
}

func TestCacheEnhancerStats(t *testing.T) {
	mock := &MockEnhancer{}
	cache, err := enhancers.NewCacheEnhancer(mock, 5*time.Minute)
	require.NoError(t, err)

	// Initial stats
	stats := cache.Stats()
	assert.Equal(t, 0, stats.Size)
	assert.Equal(t, 5*time.Minute, stats.TTL)

	// Add some items to cache
	_, err = cache.Enhance(context.Background(), authorization.ResourceContext{"key1": "value1"})
	assert.NoError(t, err)
	_, err = cache.Enhance(context.Background(), authorization.ResourceContext{"key2": "value2"})
	assert.NoError(t, err)

	// Check stats again
	stats = cache.Stats()
	assert.Equal(t, 2, stats.Size)
}

func TestInvalidatingCacheEnhancer(t *testing.T) {
	mock := &MockEnhancer{
		EnhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["enhanced"] = "true"
			return result, nil
		},
	}

	cache, err := enhancers.NewInvalidatingCacheEnhancer(mock, 5*time.Minute)
	require.NoError(t, err)

	// Test app invalidation
	appResource := authorization.ResourceContext{"appID": "app123"}
	_, err = cache.Enhance(context.Background(), appResource)
	assert.NoError(t, err)
	assert.Equal(t, 1, mock.CallCount)

	// Should hit cache
	_, err = cache.Enhance(context.Background(), appResource)
	assert.NoError(t, err)
	assert.Equal(t, 1, mock.CallCount)

	// Invalidate app
	cache.InvalidateApp("app123")

	// Should miss cache
	_, err = cache.Enhance(context.Background(), appResource)
	assert.NoError(t, err)
	assert.Equal(t, 2, mock.CallCount)

	// Test unit invalidation
	unitResource := authorization.ResourceContext{"unitID": "unit456"}
	_, err = cache.Enhance(context.Background(), unitResource)
	assert.NoError(t, err)
	assert.Equal(t, 3, mock.CallCount)

	// Should hit cache
	_, err = cache.Enhance(context.Background(), unitResource)
	assert.NoError(t, err)
	assert.Equal(t, 3, mock.CallCount)

	// Invalidate unit
	cache.InvalidateUnit("unit456")

	// Should miss cache
	_, err = cache.Enhance(context.Background(), unitResource)
	assert.NoError(t, err)
	assert.Equal(t, 4, mock.CallCount)

	// Test pattern invalidation
	_, err = cache.Enhance(context.Background(), authorization.ResourceContext{"pattern": "test"})
	assert.NoError(t, err)
	assert.Equal(t, 5, mock.CallCount)

	// Should hit cache
	_, err = cache.Enhance(context.Background(), authorization.ResourceContext{"pattern": "test"})
	assert.NoError(t, err)
	assert.Equal(t, 5, mock.CallCount)

	// Invalidate by pattern
	cache.Invalidate("test")

	// Should miss cache (pattern invalidation clears all)
	_, err = cache.Enhance(context.Background(), authorization.ResourceContext{"pattern": "test"})
	assert.NoError(t, err)
	assert.Equal(t, 6, mock.CallCount)
}
