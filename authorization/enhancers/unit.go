package enhancers

import (
	"context"

	"github.com/epfl-si/go-toolbox/authorization"
	"go.uber.org/zap"
)

// DefaultUnitInferrer infers the unitID for machine tokens that have exactly one allowed unit.
// This is a convenience for single-unit machines so they don't have to specify unitID in every request.
//
// Behavior:
//   - No-op for user tokens (users always specify the target unit via the request)
//   - No-op if resource already has a unitID (explicit always wins)
//   - No-op if machine has zero or multiple allowed units (ambiguous — caller must specify)
//   - Sets resource["unitID"] only when the machine has exactly one allowed unit
type DefaultUnitInferrer struct {
	log *zap.Logger
}

// NewDefaultUnitInferrer creates a new DefaultUnitInferrer.
func NewDefaultUnitInferrer(log *zap.Logger) authorization.ResourceEnhancer {
	if log == nil {
		log = zap.NewNop()
	}
	return &DefaultUnitInferrer{log: log}
}

// Enhance infers unitID from the machine's single allowed unit if applicable.
func (e *DefaultUnitInferrer) Enhance(ctx context.Context, resource authorization.ResourceContext) (authorization.ResourceContext, error) {
	authCtx, ok := authorization.GetAuthContextFromCtx(ctx)
	if !ok || !authCtx.IsMachine() {
		return resource, nil
	}

	if _, hasUnit := resource["unitID"]; hasUnit {
		return resource, nil
	}

	units := authCtx.GetUnits()
	if len(units) == 1 {
		result := resource.Clone()
		result["unitID"] = units[0]
		e.log.Debug("Inferred unitID from single allowed unit",
			zap.String("client_id", authCtx.GetClientID()),
			zap.String("unitID", units[0]))
		return result, nil
	}

	return resource, nil
}

// Name returns the enhancer name.
func (e *DefaultUnitInferrer) Name() string {
	return "DefaultUnitInferrer"
}
