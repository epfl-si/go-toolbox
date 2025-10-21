package enhancers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/epfl-si/go-toolbox/authorization"
)

// ParamEnhancer extracts a parameter from the URL path
type ParamEnhancer struct {
	paramName string
	targetKey string
}

// NewParamEnhancer creates a new ParamEnhancer
func NewParamEnhancer(paramName, targetKey string) *ParamEnhancer {
	return &ParamEnhancer{
		paramName: paramName,
		targetKey: targetKey,
	}
}

// Enhance extracts the parameter from gin.Context and adds it to the resource
func (e *ParamEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	ginCtx, ok := authorization.GetGinContext(ctx)
	if !ok {
		// No gin.Context available, return resource as-is
		return resource, nil
	}

	result := resource.Clone()

	// Extract parameter value
	if value := ginCtx.Param(e.paramName); value != "" {
		result[e.targetKey] = value
	}

	return result, nil
}

// Name returns a descriptive name
func (e *ParamEnhancer) Name() string {
	return fmt.Sprintf("ParamEnhancer(%s->%s)", e.paramName, e.targetKey)
}

// QueryEnhancer extracts a query parameter from the URL
type QueryEnhancer struct {
	queryName string
	targetKey string
	required  bool
}

// NewQueryEnhancer creates a new QueryEnhancer
func NewQueryEnhancer(queryName, targetKey string) *QueryEnhancer {
	return &QueryEnhancer{
		queryName: queryName,
		targetKey: targetKey,
		required:  false,
	}
}

// NewRequiredQueryEnhancer creates a new QueryEnhancer that requires the parameter
func NewRequiredQueryEnhancer(queryName, targetKey string) *QueryEnhancer {
	return &QueryEnhancer{
		queryName: queryName,
		targetKey: targetKey,
		required:  true,
	}
}

// Enhance extracts the query parameter from gin.Context and adds it to the resource
func (e *QueryEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	ginCtx, ok := authorization.GetGinContext(ctx)
	if !ok {
		return resource, nil
	}

	result := resource.Clone()

	// Extract query value
	value := ginCtx.Query(e.queryName)
	if value != "" {
		result[e.targetKey] = value
	} else if e.required {
		return resource, fmt.Errorf("required query parameter '%s' not found", e.queryName)
	}

	return result, nil
}

// Name returns a descriptive name
func (e *QueryEnhancer) Name() string {
	if e.required {
		return fmt.Sprintf("QueryEnhancer(%s->%s,required)", e.queryName, e.targetKey)
	}
	return fmt.Sprintf("QueryEnhancer(%s->%s)", e.queryName, e.targetKey)
}

// BodyEnhancer extracts data from the request body
type BodyEnhancer struct {
	sourcePaths []string // JSON paths to extract from body
	targetKey   string   // Key to store in ResourceContext
}

// NewBodyEnhancer creates a new BodyEnhancer that looks for value at multiple possible paths
func NewBodyEnhancer(sourcePaths []string, targetKey string) *BodyEnhancer {
	return &BodyEnhancer{
		sourcePaths: sourcePaths,
		targetKey:   targetKey,
	}
}

// NewSimpleBodyEnhancer creates a BodyEnhancer for a single path
func NewSimpleBodyEnhancer(sourcePath, targetKey string) *BodyEnhancer {
	return &BodyEnhancer{
		sourcePaths: []string{sourcePath},
		targetKey:   targetKey,
	}
}

// Enhance extracts data from the request body and adds it to the resource
// This implementation preserves the request body for subsequent handlers
func (e *BodyEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	ginCtx, ok := authorization.GetGinContext(ctx)
	if !ok {
		return resource, nil
	}

	result := resource.Clone()

	// Save and restore the request body to allow it to be read again by handlers
	if ginCtx.Request != nil && ginCtx.Request.Body != nil {
		// Read the body
		bodyBytes, err := io.ReadAll(ginCtx.Request.Body)
		if err != nil {
			// If we can't read the body, return without error
			return result, nil
		}

		// Restore the body for subsequent readers
		ginCtx.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Parse the body as JSON
		var bodyData map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
			// If we can't parse the JSON, just return without error
			return result, nil
		}

		// Look for the value at any of the specified paths
		for _, path := range e.sourcePaths {
			value := e.extractValueFromPath(bodyData, path)
			if value != nil {
				// Convert value to string if possible
				if strValue, ok := value.(string); ok {
					result[e.targetKey] = strValue
				} else {
					// For non-string values, store as JSON string
					if jsonBytes, err := json.Marshal(value); err == nil {
						result[e.targetKey] = string(jsonBytes)
					}
				}
				break // Found a value, stop searching
			}
		}
	}

	return result, nil
}

// extractValueFromPath extracts a value from nested map using dot notation path
func (e *BodyEnhancer) extractValueFromPath(data map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
			if current == nil {
				return nil
			}
		default:
			return nil
		}
	}

	return current
}

// Name returns a descriptive name
func (e *BodyEnhancer) Name() string {
	if len(e.sourcePaths) == 1 {
		return fmt.Sprintf("BodyEnhancer(%s->%s)", e.sourcePaths[0], e.targetKey)
	}
	return fmt.Sprintf("BodyEnhancer([%s]->%s)", strings.Join(e.sourcePaths, ","), e.targetKey)
}

// HeaderEnhancer extracts a header value from the request
type HeaderEnhancer struct {
	headerName string
	targetKey  string
}

// NewHeaderEnhancer creates a new HeaderEnhancer
func NewHeaderEnhancer(headerName, targetKey string) *HeaderEnhancer {
	return &HeaderEnhancer{
		headerName: headerName,
		targetKey:  targetKey,
	}
}

// Enhance extracts the header from gin.Context and adds it to the resource
func (e *HeaderEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	ginCtx, ok := authorization.GetGinContext(ctx)
	if !ok {
		return resource, nil
	}

	result := resource.Clone()

	// Extract header value
	if value := ginCtx.GetHeader(e.headerName); value != "" {
		result[e.targetKey] = value
	}

	return result, nil
}

// Name returns a descriptive name
func (e *HeaderEnhancer) Name() string {
	return fmt.Sprintf("HeaderEnhancer(%s->%s)", e.headerName, e.targetKey)
}

// MultiParamEnhancer extracts multiple parameters at once
type MultiParamEnhancer struct {
	mappings map[string]string // paramName -> targetKey
}

// NewMultiParamEnhancer creates a new MultiParamEnhancer
func NewMultiParamEnhancer(mappings map[string]string) *MultiParamEnhancer {
	return &MultiParamEnhancer{
		mappings: mappings,
	}
}

// Enhance extracts multiple parameters and adds them to the resource
func (e *MultiParamEnhancer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	ginCtx, ok := authorization.GetGinContext(ctx)
	if !ok {
		return resource, nil
	}

	result := resource.Clone()

	// Extract all mapped parameters
	for paramName, targetKey := range e.mappings {
		if value := ginCtx.Param(paramName); value != "" {
			result[targetKey] = value
		}
	}

	return result, nil
}

// Name returns a descriptive name
func (e *MultiParamEnhancer) Name() string {
	pairs := make([]string, 0, len(e.mappings))
	for param, target := range e.mappings {
		pairs = append(pairs, fmt.Sprintf("%s->%s", param, target))
	}
	return fmt.Sprintf("MultiParamEnhancer([%s])", strings.Join(pairs, ","))
}
