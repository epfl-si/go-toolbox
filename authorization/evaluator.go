package authorization

import (
	"fmt"

	"go.uber.org/zap"
)

// PolicyEvaluator makes the actual authorization decisions
type PolicyEvaluator struct {
	config *Config
	log    *zap.Logger
}

// NewPolicyEvaluator creates a new policy evaluator
func NewPolicyEvaluator(config *Config, log *zap.Logger) *PolicyEvaluator {
	if config == nil {
		config = GetDefaultConfig()
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &PolicyEvaluator{
		config: config,
		log:    log,
	}
}

// Evaluate determines if an action is authorized and provides a reason.
//
// The evaluation follows a single unified code path for both users and machines:
//
//	PRIORITY 1: System permissions (role-based, no unit scoping)
//	PRIORITY 2: Global role permissions (bypass unit scoping)
//	PRIORITY 3: Unit-scoped permissions (actor's units vs resource's unitID)
//	PRIORITY 4: Default deny
//
// Unit data is read from authCtx.GetUnits() for both users and machines.
// The actor's identity type only affects reason string prefixes and log levels.
func (e *PolicyEvaluator) Evaluate(authCtx AuthContext, permission Permission, resource ResourceContext) (bool, string) {
	e.log.Debug("Evaluating authorization",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.String("permission", permission.String()),
		zap.Bool("is_user", authCtx.IsUser()),
		zap.Bool("is_machine", authCtx.IsMachine()),
	)

	// System-level permissions are role-based only, no unit scoping
	if permission.Resource == "system" {
		return e.evaluateSystemPermission(authCtx, permission)
	}

	// Unified role resolution: direct roles + group-mapped roles, deduplicated
	roles := e.getRoles(authCtx)

	// Prefix distinguishes user/machine in reason strings and logs
	prefix := "user_"
	if authCtx.IsMachine() {
		prefix = "machine_"
	}

	// PRIORITY 1: Global role permissions bypass unit scoping
	for _, role := range roles {
		if e.config.HasRolePermission(role, permission) {
			reason := fmt.Sprintf("%sglobal_role_bypass_%s", prefix, role)
			e.log.Debug("Permission granted via global role bypass",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("permission", permission.String()),
				zap.String("role", role),
				zap.String("reason", reason),
			)
			return true, reason
		}
	}

	// PRIORITY 2: Unit-scoped permissions
	if unitID, ok := resource["unitID"]; ok && unitID != "" {
		identityUnits := authCtx.GetUnits()

		// Distinguish "no units configured" from "wrong unit"
		if len(identityUnits) == 0 {
			reason := prefix + "no_units_configured"
			e.log.Warn("Identity has no units configured",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.Bool("is_machine", authCtx.IsMachine()),
				zap.String("required_unit", unitID),
				zap.String("reason", reason),
			)
			return false, reason
		}

		for _, unit := range identityUnits {
			if unit == unitID {
				// Unit matches — check unit-scoped permissions
				for _, role := range roles {
					if e.hasUnitScopedPermission(role, permission) {
						reason := fmt.Sprintf("%sunit_match_%s", prefix, role)
						e.log.Debug("Permission granted via unit match",
							zap.String("identifier", authCtx.GetIdentifier()),
							zap.String("permission", permission.String()),
							zap.String("unit", unitID),
							zap.String("role", role),
							zap.String("reason", reason),
						)
						return true, reason
					}
				}
				// Unit matched but no role grants permission
				reason := fmt.Sprintf("%sunit_match_no_permission_%s", prefix, unitID)
				e.log.Debug("Permission denied - unit matched but no role has permission",
					zap.String("identifier", authCtx.GetIdentifier()),
					zap.String("permission", permission.String()),
					zap.String("unit", unitID),
					zap.Strings("roles", roles),
					zap.String("reason", reason),
				)
				return false, reason
			}
		}

		// No unit matched
		reason := fmt.Sprintf("%sunit_mismatch_required_%s", prefix, unitID)
		if authCtx.IsMachine() {
			e.log.Warn("Machine token denied - unit mismatch",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("client_id", authCtx.GetClientID()),
				zap.String("required_unit", unitID),
				zap.Strings("allowed_units", identityUnits),
				zap.String("reason", reason),
			)
		} else {
			e.log.Debug("Permission denied - unit mismatch",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("permission", permission.String()),
				zap.String("required_unit", unitID),
				zap.Strings("identity_units", identityUnits),
				zap.String("reason", reason),
			)
		}
		return false, reason
	}

	// PRIORITY 3: No global permission and no unit scope — deny
	reason := prefix + "not_authorized"
	e.log.Debug("Permission denied",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.String("permission", permission.String()),
		zap.Strings("roles", roles),
		zap.String("reason", reason),
	)
	return false, reason
}

// evaluateSystemPermission evaluates system-level permissions
func (e *PolicyEvaluator) evaluateSystemPermission(authCtx AuthContext, permission Permission) (bool, string) {
	roles := e.getRoles(authCtx)

	for _, role := range roles {
		if e.config.HasRolePermission(role, permission) {
			reason := fmt.Sprintf("system_permission_via_role_%s", role)
			e.log.Debug("System permission granted",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("permission", permission.String()),
				zap.String("reason", reason),
			)
			return true, reason
		}
	}

	reason := "system_permission_denied"
	e.log.Debug("System permission denied",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.String("permission", permission.String()),
		zap.String("reason", reason),
	)
	return false, reason
}

// getRoles gets all roles for an auth context (direct + group-mapped, deduplicated)
func (e *PolicyEvaluator) getRoles(authCtx AuthContext) []string {
	directRoles := authCtx.GetRoles()
	groupRoles := e.getRolesFromGroups(authCtx.GetGroups())

	roleSet := make(map[string]bool)
	for _, role := range directRoles {
		roleSet[role] = true
	}
	for _, role := range groupRoles {
		roleSet[role] = true
	}

	result := make([]string, 0, len(roleSet))
	for role := range roleSet {
		result = append(result, role)
	}
	return result
}

// getRolesFromGroups translates AD groups to internal roles
func (e *PolicyEvaluator) getRolesFromGroups(groups []string) []string {
	return e.config.GetRolesForGroups(groups)
}

// hasUnitScopedPermission checks if a role has unit-scoped permissions
func (e *PolicyEvaluator) hasUnitScopedPermission(role string, permission Permission) bool {
	return e.config.HasUnitScopedPermission(role, permission)
}
