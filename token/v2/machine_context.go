package token

import "github.com/gin-gonic/gin"

// MachineContext represents the context extracted from a machine/application token
type MachineContext struct {
	ApplicationID      string   `json:"app_id"`               // The application/client ID (azp or appid)
	ServicePrincipalID string   `json:"service_principal_id"` // The service principal object ID (oid)
	Roles              []string `json:"roles"`                // Application roles
	Identity           string   `json:"identity"`             // Unified identity string for logging
}

// ExtractMachineContext extracts machine-specific context from unified claims.
// Returns nil if the token is not a machine token.
func ExtractMachineContext(claims *UnifiedClaims) *MachineContext {
	if GetTokenType(claims) != TypeMachine {
		return nil
	}

	return &MachineContext{
		ApplicationID:      GetApplicationID(claims),
		ServicePrincipalID: GetServicePrincipalID(claims),
		Roles:              claims.Roles,
		Identity:           GetIdentity(claims),
	}
}

// GetMachineContext extracts MachineContext from gin.Context
// Returns nil if not present or not a machine token
func GetMachineContext(c *gin.Context) *MachineContext {
	if ctx, exists := c.Get(string(ContextKeyMachineCtx)); exists {
		if machineCtx, ok := ctx.(*MachineContext); ok {
			return machineCtx
		}
	}
	return nil
}
