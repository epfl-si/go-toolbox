package enhancers

import (
	"context"
	"testing"

	"github.com/epfl-si/go-toolbox/authorization"
	"github.com/stretchr/testify/assert"
)

func TestDefaultUnitInferrer_MachineWithSingleUnit(t *testing.T) {
	inferrer := NewDefaultUnitInferrer(nil)

	machineCtx := &authorization.MachineAuthContext{
		ServicePrincipalID: "sp-1",
		ClientID:           "client-1",
		AllowedUnits:       []string{"unit-123"},
	}

	ctx := authorization.WithAuthContext(context.Background(), machineCtx)
	resource := authorization.ResourceContext{"appID": "app-1"}

	result, err := inferrer.Enhance(ctx, resource)
	assert.NoError(t, err)
	assert.Equal(t, "unit-123", result["unitID"])
	assert.Equal(t, "app-1", result["appID"])
}

func TestDefaultUnitInferrer_MachineWithMultipleUnits(t *testing.T) {
	inferrer := NewDefaultUnitInferrer(nil)

	machineCtx := &authorization.MachineAuthContext{
		ServicePrincipalID: "sp-1",
		ClientID:           "client-1",
		AllowedUnits:       []string{"unit-123", "unit-456"},
	}

	ctx := authorization.WithAuthContext(context.Background(), machineCtx)
	resource := authorization.ResourceContext{"appID": "app-1"}

	result, err := inferrer.Enhance(ctx, resource)
	assert.NoError(t, err)
	assert.Empty(t, result["unitID"], "should not infer unitID when machine has multiple units")
}

func TestDefaultUnitInferrer_MachineWithNoUnits(t *testing.T) {
	inferrer := NewDefaultUnitInferrer(nil)

	machineCtx := &authorization.MachineAuthContext{
		ServicePrincipalID: "sp-1",
		ClientID:           "client-1",
	}

	ctx := authorization.WithAuthContext(context.Background(), machineCtx)
	resource := authorization.ResourceContext{"appID": "app-1"}

	result, err := inferrer.Enhance(ctx, resource)
	assert.NoError(t, err)
	assert.Empty(t, result["unitID"])
}

func TestDefaultUnitInferrer_MachineWithExistingUnitID(t *testing.T) {
	inferrer := NewDefaultUnitInferrer(nil)

	machineCtx := &authorization.MachineAuthContext{
		ServicePrincipalID: "sp-1",
		ClientID:           "client-1",
		AllowedUnits:       []string{"unit-123"},
	}

	ctx := authorization.WithAuthContext(context.Background(), machineCtx)
	resource := authorization.ResourceContext{"unitID": "unit-456"}

	result, err := inferrer.Enhance(ctx, resource)
	assert.NoError(t, err)
	assert.Equal(t, "unit-456", result["unitID"], "should not overwrite existing unitID")
}

func TestDefaultUnitInferrer_UserToken(t *testing.T) {
	inferrer := NewDefaultUnitInferrer(nil)

	userCtx := &authorization.UserAuthContext{
		UniqueID: "user-1",
		Units:    []string{"unit-123"},
	}

	ctx := authorization.WithAuthContext(context.Background(), userCtx)
	resource := authorization.ResourceContext{"appID": "app-1"}

	result, err := inferrer.Enhance(ctx, resource)
	assert.NoError(t, err)
	assert.Empty(t, result["unitID"], "should not infer unitID for user tokens")
}

func TestDefaultUnitInferrer_NoAuthContext(t *testing.T) {
	inferrer := NewDefaultUnitInferrer(nil)

	resource := authorization.ResourceContext{"appID": "app-1"}

	result, err := inferrer.Enhance(context.Background(), resource)
	assert.NoError(t, err)
	assert.Empty(t, result["unitID"])
}

func TestDefaultUnitInferrer_Name(t *testing.T) {
	inferrer := NewDefaultUnitInferrer(nil)
	assert.Equal(t, "DefaultUnitInferrer", inferrer.Name())
}
