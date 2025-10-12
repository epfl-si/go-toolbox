package authorization

import (
	"context"

	"github.com/gin-gonic/gin"
)

// ResourceEnhancer can enrich a ResourceContext from any source.
// It unifies the concepts of extraction and resolution into a single, composable interface.
type ResourceEnhancer interface {
	// Enhance enriches the ResourceContext with additional information.
	// The context may contain gin.Context via a special key.
	Enhance(ctx context.Context, resource ResourceContext) (ResourceContext, error)

	// Name returns a descriptive name for logging/debugging
	Name() string
}

// enhancerContextKey is the internal key for storing gin.Context in context.Context
type enhancerContextKey struct{}

// WithGinContext adds gin.Context to context.Context for enhancers
func WithGinContext(ctx context.Context, ginCtx *gin.Context) context.Context {
	return context.WithValue(ctx, enhancerContextKey{}, ginCtx)
}

// GetGinContext retrieves gin.Context from context.Context for enhancers
func GetGinContext(ctx context.Context) (*gin.Context, bool) {
	ginCtx, ok := ctx.Value(enhancerContextKey{}).(*gin.Context)
	return ginCtx, ok
}
