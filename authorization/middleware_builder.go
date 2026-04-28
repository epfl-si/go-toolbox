package authorization

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Middleware bundles a Service and DefaultExtractor for convenient route setup.
type Middleware struct {
	service   *Service
	extractor gin.HandlerFunc
	log       *zap.Logger
}

// NewMiddleware creates a Middleware from ExtractorOptions.
func NewMiddleware(opts ExtractorOptions) *Middleware {
	return &Middleware{
		service:   NewDefaultService(opts.Config, opts.Log),
		extractor: DefaultExtractor(opts),
		log:       opts.Log,
	}
}

// ExtractAuthContext returns the gin handler that populates AuthContext.
func (m *Middleware) ExtractAuthContext() gin.HandlerFunc { return m.extractor }

// RequirePermission delegates to the service's permission middleware.
func (m *Middleware) RequirePermission(p Permission, e ResourceEnhancer) gin.HandlerFunc {
	return RequirePermission(p, e, m.service.GetAuthorizer(), m.log)
}

// RequireAnyPermission delegates to the service's any-permission middleware.
func (m *Middleware) RequireAnyPermission(ps []Permission, e ResourceEnhancer) gin.HandlerFunc {
	return RequireAnyPermission(ps, e, m.service.GetAuthorizer(), m.log)
}

// Service returns the underlying authorization service.
func (m *Middleware) Service() *Service { return m.service }
