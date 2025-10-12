package enhancers

import (
	"context"
	"fmt"
	"strings"

	"github.com/epfl-si/go-toolbox/authorization"
	"go.uber.org/zap"
)

// ChainEnhancer composes multiple enhancers in sequence
type ChainEnhancer struct {
	enhancers []authorization.ResourceEnhancer
	log       *zap.Logger
}

// NewChainEnhancer creates a new chain of enhancers
func NewChainEnhancer(enhancers ...authorization.ResourceEnhancer) *ChainEnhancer {
	log, _ := zap.NewProduction()
	return &ChainEnhancer{
		enhancers: enhancers,
		log:       log,
	}
}

// NewChainEnhancerWithLogger creates a new chain with a custom logger
func NewChainEnhancerWithLogger(log *zap.Logger, enhancers ...authorization.ResourceEnhancer) *ChainEnhancer {
	if log == nil {
		log = zap.NewNop()
	}
	return &ChainEnhancer{
		enhancers: enhancers,
		log:       log,
	}
}

// Enhance runs all enhancers in sequence, passing the result of each to the next
func (e *ChainEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	if resource == nil {
		resource = make(authorization.ResourceContext)
	}

	result := resource.Clone()

	for _, enhancer := range e.enhancers {
		if enhancer == nil {
			continue
		}

		enhanced, err := enhancer.Enhance(ctx, result)
		if err != nil {
			// Log the error but continue with other enhancers
			e.log.Warn("Enhancer failed, continuing with chain",
				zap.String("enhancer", enhancer.Name()),
				zap.Error(err))
			continue
		}

		result = enhanced
	}

	return result, nil
}

// Name returns a descriptive name showing the chain of enhancers
func (e *ChainEnhancer) Name() string {
	if len(e.enhancers) == 0 {
		return "Chain[]"
	}

	names := make([]string, 0, len(e.enhancers))
	for _, enhancer := range e.enhancers {
		if enhancer != nil {
			names = append(names, enhancer.Name())
		}
	}

	return fmt.Sprintf("Chain[%s]", strings.Join(names, "->"))
}

// Add adds more enhancers to the chain
func (e *ChainEnhancer) Add(enhancers ...authorization.ResourceEnhancer) *ChainEnhancer {
	e.enhancers = append(e.enhancers, enhancers...)
	return e
}

// Length returns the number of enhancers in the chain
func (e *ChainEnhancer) Length() int {
	return len(e.enhancers)
}
