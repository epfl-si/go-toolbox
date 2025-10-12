package enhancers_test

import (
	"context"
	"testing"
	"time"

	"github.com/epfl-si/go-toolbox/authorization"
	"github.com/epfl-si/go-toolbox/authorization/enhancers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CountingEnhancer is a test enhancer that counts how many times it's called
type CountingEnhancer struct {
	name        string
	enhanceFunc func(context.Context, authorization.ResourceContext) (authorization.ResourceContext, error)
	CallCount   int
}

func (e *CountingEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	e.CallCount++
	if e.enhanceFunc != nil {
		return e.enhanceFunc(ctx, resource)
	}
	return resource, nil
}

func (e *CountingEnhancer) Name() string {
	if e.name != "" {
		return e.name
	}
	return "CountingEnhancer"
}

// TestCacheWithChainEnhancer tests the integration between CacheEnhancer and ChainEnhancer
func TestCacheWithChainEnhancer(t *testing.T) {
	// Create enhancers for the chain
	enhancer1 := &CountingEnhancer{
		name: "enhancer1",
		enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["step1"] = "done"
			return result, nil
		},
	}

	enhancer2 := &CountingEnhancer{
		name: "enhancer2",
		enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["step2"] = "done"
			return result, nil
		},
	}

	// Create a chain enhancer
	chain := enhancers.NewChainEnhancer(enhancer1, enhancer2)

	// Wrap the chain with a cache enhancer
	cache, err := enhancers.NewCacheEnhancer(chain, 5*time.Minute)
	require.NoError(t, err)

	// First call - should miss cache and call both enhancers in the chain
	resource := authorization.ResourceContext{"original": "value"}
	result1, err := cache.Enhance(context.Background(), resource)
	require.NoError(t, err)

	// Verify the result contains all expected values
	assert.Equal(t, "value", result1["original"])
	assert.Equal(t, "done", result1["step1"])
	assert.Equal(t, "done", result1["step2"])

	// Verify the enhancers were called
	assert.Equal(t, 1, enhancer1.CallCount)
	assert.Equal(t, 1, enhancer2.CallCount)

	// Second call with same resource - should hit cache and not call enhancers
	result2, err := cache.Enhance(context.Background(), resource)
	require.NoError(t, err)

	// Verify the result is the same
	assert.Equal(t, result1, result2)

	// Verify the enhancers were not called again
	assert.Equal(t, 1, enhancer1.CallCount)
	assert.Equal(t, 1, enhancer2.CallCount)

	// Clear the cache
	cache.Clear()

	// Third call after clearing cache - should miss and call enhancers again
	result3, err := cache.Enhance(context.Background(), resource)
	require.NoError(t, err)

	// Verify the result is the same
	assert.Equal(t, result1, result3)

	// Verify the enhancers were called again
	assert.Equal(t, 2, enhancer1.CallCount)
	assert.Equal(t, 2, enhancer2.CallCount)
}

// TestNestedCacheEnhancers tests caching at different levels of the enhancer chain
func TestNestedCacheEnhancers(t *testing.T) {
	// Create a base enhancer
	baseEnhancer := &CountingEnhancer{
		name: "baseEnhancer",
		enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["base"] = "processed"
			return result, nil
		},
	}

	// Create a cache for the base enhancer
	innerCache, err := enhancers.NewCacheEnhancer(baseEnhancer, 5*time.Minute)
	require.NoError(t, err)

	// Create a second enhancer that will be added to the chain after the cached base enhancer
	secondEnhancer := &CountingEnhancer{
		name: "secondEnhancer",
		enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["second"] = "processed"
			return result, nil
		},
	}

	// Create a chain with the inner cache and second enhancer
	chain := enhancers.NewChainEnhancer(innerCache, secondEnhancer)

	// Create an outer cache for the entire chain
	outerCache, err := enhancers.NewCacheEnhancer(chain, 5*time.Minute)
	require.NoError(t, err)

	// First call - should miss both caches
	resource := authorization.ResourceContext{"original": "value"}
	result1, err := outerCache.Enhance(context.Background(), resource)
	require.NoError(t, err)

	// Verify the result contains all expected values
	assert.Equal(t, "value", result1["original"])
	assert.Equal(t, "processed", result1["base"])
	assert.Equal(t, "processed", result1["second"])

	// Verify the enhancers were called
	assert.Equal(t, 1, baseEnhancer.CallCount)
	assert.Equal(t, 1, secondEnhancer.CallCount)

	// Second call - should hit outer cache and not call any enhancers
	_, err = outerCache.Enhance(context.Background(), resource)
	require.NoError(t, err)

	// Verify the enhancers were not called again
	assert.Equal(t, 1, baseEnhancer.CallCount)
	assert.Equal(t, 1, secondEnhancer.CallCount)

	// Clear outer cache but keep inner cache
	outerCache.Clear()

	// Third call - should miss outer cache but hit inner cache for baseEnhancer
	_, err = outerCache.Enhance(context.Background(), resource)
	require.NoError(t, err)

	// Verify baseEnhancer wasn't called (inner cache hit) but secondEnhancer was
	assert.Equal(t, 1, baseEnhancer.CallCount)
	assert.Equal(t, 2, secondEnhancer.CallCount)

	// Clear inner cache
	innerCache.Clear()

	// Fourth call - should miss both caches
	_, err = outerCache.Enhance(context.Background(), resource)
	require.NoError(t, err)

	// Verify both enhancers were called again
	// Note: The actual behavior depends on how the cache is implemented
	// When we clear the inner cache, the outer cache still has a cached result
	// So we need to clear the outer cache as well to force a full refresh
	outerCache.Clear()
	_, err = outerCache.Enhance(context.Background(), resource)
	require.NoError(t, err)

	// Now both enhancers should have been called again
	assert.Equal(t, 2, baseEnhancer.CallCount)
	assert.Equal(t, 3, secondEnhancer.CallCount)
}
