package enhancers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/epfl-si/go-toolbox/authorization"
	gocache "github.com/patrickmn/go-cache"
	"go.uber.org/zap"
)

// CacheEnhancer adds caching to any enhancer
type CacheEnhancer struct {
	inner authorization.ResourceEnhancer
	cache *gocache.Cache
	ttl   time.Duration
	log   *zap.Logger
}

// NewCacheEnhancer creates a new CacheEnhancer wrapping another enhancer
func NewCacheEnhancer(inner authorization.ResourceEnhancer, ttl time.Duration) (*CacheEnhancer, error) {
	return NewCacheEnhancerWithLogger(inner, ttl, nil)
}

// NewCacheEnhancerWithLogger creates a new CacheEnhancer with a custom logger
func NewCacheEnhancerWithLogger(inner authorization.ResourceEnhancer, ttl time.Duration, log *zap.Logger) (*CacheEnhancer, error) {
	if inner == nil {
		return nil, fmt.Errorf("inner enhancer cannot be nil")
	}

	if log == nil {
		log = zap.NewNop()
	}

	// Create cache with TTL and cleanup interval
	cache := gocache.New(ttl, ttl*2)

	return &CacheEnhancer{
		inner: inner,
		cache: cache,
		ttl:   ttl,
		log:   log,
	}, nil
}

// Enhance checks the cache first, then calls the inner enhancer if needed
func (e *CacheEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	if resource == nil {
		resource = make(authorization.ResourceContext)
	}

	// Generate cache key from the resource context
	key := e.generateKey(resource)

	// Check cache
	if cached, found := e.cache.Get(key); found {
		if resourceCtx, ok := cached.(authorization.ResourceContext); ok {
			e.log.Debug("Cache hit",
				zap.String("key", key))
			// Return a clone to prevent cache corruption
			return resourceCtx.Clone(), nil
		}
	}

	// Cache miss, call inner enhancer
	e.log.Debug("Cache miss, calling inner enhancer",
		zap.String("key", key),
		zap.String("inner", e.inner.Name()))

	result, err := e.inner.Enhance(ctx, resource)
	if err != nil {
		// Don't cache errors
		return resource, err
	}

	// Store in cache with TTL
	e.cache.Set(key, result.Clone(), e.ttl)

	e.log.Debug("Cached result",
		zap.String("key", key),
		zap.Duration("ttl", e.ttl))

	return result, nil
}

// Name returns a descriptive name showing the cached enhancer
func (e *CacheEnhancer) Name() string {
	return fmt.Sprintf("Cache[%s,ttl=%s]", e.inner.Name(), e.ttl)
}

// generateKey creates a cache key from the resource context
func (e *CacheEnhancer) generateKey(resource authorization.ResourceContext) string {
	// Priority-based key generation for common cases

	// For application-based resources
	if appID, ok := resource["appID"]; ok && appID != "" {
		return fmt.Sprintf("app:%s", appID)
	}

	// For config-based resources
	if configID, ok := resource["configID"]; ok && configID != "" {
		return fmt.Sprintf("config:%s", configID)
	}

	// For unit-based resources
	if unitID, ok := resource["unitID"]; ok && unitID != "" {
		return fmt.Sprintf("unit:%s", unitID)
	}

	// For numeric IDs
	if id, ok := resource["id"]; ok && id != "" {
		return fmt.Sprintf("id:%s", id)
	}

	// Fallback to JSON representation of the entire context
	// This ensures uniqueness but might be slower
	data, err := json.Marshal(resource)
	if err != nil {
		// If marshaling fails, use a timestamp-based key (no caching)
		return fmt.Sprintf("error:%d", time.Now().UnixNano())
	}

	return string(data)
}

// Clear removes all entries from the cache
func (e *CacheEnhancer) Clear() {
	e.cache.Flush()
	e.log.Info("Cache cleared")
}

// Size returns the current number of items in the cache
func (e *CacheEnhancer) Size() int {
	return e.cache.ItemCount()
}

// Stats provides cache statistics
type CacheStats struct {
	Size     int           `json:"size"`
	Capacity int           `json:"capacity"`
	TTL      time.Duration `json:"ttl"`
}

// Stats returns current cache statistics
func (e *CacheEnhancer) Stats() CacheStats {
	return CacheStats{
		Size:     e.cache.ItemCount(),
		Capacity: -1, // go-cache doesn't have a fixed capacity
		TTL:      e.ttl,
	}
}

// InvalidatingCacheEnhancer is a cache that can be selectively invalidated
type InvalidatingCacheEnhancer struct {
	*CacheEnhancer
	invalidationPatterns map[string]func(authorization.ResourceContext) bool
}

// NewInvalidatingCacheEnhancer creates a cache with invalidation support
func NewInvalidatingCacheEnhancer(inner authorization.ResourceEnhancer, ttl time.Duration) (*InvalidatingCacheEnhancer, error) {
	base, err := NewCacheEnhancer(inner, ttl)
	if err != nil {
		return nil, err
	}

	return &InvalidatingCacheEnhancer{
		CacheEnhancer:        base,
		invalidationPatterns: make(map[string]func(authorization.ResourceContext) bool),
	}, nil
}

// Invalidate removes entries matching a pattern
func (e *InvalidatingCacheEnhancer) Invalidate(pattern string) {
	// This is a simplified version - in production, you'd track keys
	// and invalidate based on patterns
	e.log.Info("Invalidating cache entries",
		zap.String("pattern", pattern))

	// For now, clear everything when invalidation is requested
	e.Clear()
}

// InvalidateApp removes all cache entries for a specific application
func (e *InvalidatingCacheEnhancer) InvalidateApp(appID string) {
	key := fmt.Sprintf("app:%s", appID)
	e.cache.Delete(key)
	e.log.Debug("Invalidated app cache",
		zap.String("appID", appID))
}

// InvalidateUnit removes all cache entries for a specific unit
func (e *InvalidatingCacheEnhancer) InvalidateUnit(unitID string) {
	key := fmt.Sprintf("unit:%s", unitID)
	e.cache.Delete(key)
	e.log.Debug("Invalidated unit cache",
		zap.String("unitID", unitID))
}
