package enhancers_test

import (
	"context"
	"testing"

	"github.com/epfl-si/go-toolbox/authorization"
	"github.com/epfl-si/go-toolbox/authorization/enhancers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestChainEnhancer tests the ChainEnhancer functionality
func TestChainEnhancer(t *testing.T) {
	tests := []struct {
		name      string
		enhancers []authorization.ResourceEnhancer
		input     authorization.ResourceContext
		expected  authorization.ResourceContext
	}{
		{
			name:      "empty chain",
			enhancers: []authorization.ResourceEnhancer{},
			input:     authorization.ResourceContext{"original": "value"},
			expected:  authorization.ResourceContext{"original": "value"},
		},
		{
			name: "single enhancer",
			enhancers: []authorization.ResourceEnhancer{
				&testEnhancer{
					name: "enhancer1",
					enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
						result := resource.Clone()
						result["added"] = "value1"
						return result, nil
					},
				},
			},
			input:    authorization.ResourceContext{"original": "value"},
			expected: authorization.ResourceContext{"original": "value", "added": "value1"},
		},
		{
			name: "multiple enhancers",
			enhancers: []authorization.ResourceEnhancer{
				&testEnhancer{
					name: "enhancer1",
					enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
						result := resource.Clone()
						result["step1"] = "done"
						return result, nil
					},
				},
				&testEnhancer{
					name: "enhancer2",
					enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
						result := resource.Clone()
						result["step2"] = "done"
						return result, nil
					},
				},
				&testEnhancer{
					name: "enhancer3",
					enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
						result := resource.Clone()
						// This enhancer can see previous values
						if result["step1"] == "done" && result["step2"] == "done" {
							result["all_steps"] = "complete"
						}
						return result, nil
					},
				},
			},
			input: authorization.ResourceContext{"original": "value"},
			expected: authorization.ResourceContext{
				"original":  "value",
				"step1":     "done",
				"step2":     "done",
				"all_steps": "complete",
			},
		},
		{
			name: "chain with nil enhancer",
			enhancers: []authorization.ResourceEnhancer{
				&testEnhancer{
					name: "enhancer1",
					enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
						result := resource.Clone()
						result["before_nil"] = "value"
						return result, nil
					},
				},
				nil, // nil enhancer should be skipped
				&testEnhancer{
					name: "enhancer2",
					enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
						result := resource.Clone()
						result["after_nil"] = "value"
						return result, nil
					},
				},
			},
			input: authorization.ResourceContext{},
			expected: authorization.ResourceContext{
				"before_nil": "value",
				"after_nil":  "value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := enhancers.NewChainEnhancer(tt.enhancers...)

			result, err := chain.Enhance(context.Background(), tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)

			// Test Name() method
			assert.Contains(t, chain.Name(), "Chain")

			// Test Length() method
			nonNilCount := 0
			for _, e := range tt.enhancers {
				if e != nil {
					nonNilCount++
				}
			}
			assert.Equal(t, len(tt.enhancers), chain.Length())
		})
	}
}

// TestChainEnhancerWithError tests error handling in ChainEnhancer
func TestChainEnhancerWithError(t *testing.T) {
	log := zap.NewNop()

	enhancerList := []authorization.ResourceEnhancer{
		&testEnhancer{
			name: "enhancer1",
			enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
				result := resource.Clone()
				result["step1"] = "done"
				return result, nil
			},
		},
		&testEnhancer{
			name: "failing_enhancer",
			enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
				return nil, assert.AnError
			},
		},
		&testEnhancer{
			name: "enhancer3",
			enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
				result := resource.Clone()
				result["step3"] = "done"
				return result, nil
			},
		},
	}

	chain := enhancers.NewChainEnhancerWithLogger(log, enhancerList...)

	input := authorization.ResourceContext{"original": "value"}
	result, err := chain.Enhance(context.Background(), input)

	// Chain should continue despite error and not fail
	assert.NoError(t, err)

	// Should have results from enhancers that didn't fail
	assert.Equal(t, "value", result["original"])
	assert.Equal(t, "done", result["step1"])
	assert.Equal(t, "done", result["step3"])
	assert.NotContains(t, result, "failing_enhancer")
}

// TestChainEnhancerAdd tests the Add method
func TestChainEnhancerAdd(t *testing.T) {
	chain := enhancers.NewChainEnhancer()

	assert.Equal(t, 0, chain.Length())

	// Add first enhancer
	chain.Add(&testEnhancer{
		name: "enhancer1",
		enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["first"] = "value"
			return result, nil
		},
	})

	assert.Equal(t, 1, chain.Length())

	// Add second enhancer
	chain.Add(&testEnhancer{
		name: "enhancer2",
		enhanceFunc: func(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
			result := resource.Clone()
			result["second"] = "value"
			return result, nil
		},
	})

	assert.Equal(t, 2, chain.Length())

	// Test that both enhancers work
	result, err := chain.Enhance(context.Background(), authorization.ResourceContext{})
	require.NoError(t, err)
	assert.Equal(t, "value", result["first"])
	assert.Equal(t, "value", result["second"])
}

// testEnhancer is a mock enhancer for testing
type testEnhancer struct {
	name        string
	enhanceFunc func(context.Context, authorization.ResourceContext) (authorization.ResourceContext, error)
}

func (e *testEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	if e.enhanceFunc != nil {
		return e.enhanceFunc(ctx, resource)
	}
	return resource, nil
}

func (e *testEnhancer) Name() string {
	return e.name
}
