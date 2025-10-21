package authorization

import (
	"fmt"
	"strings"

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

// Evaluate determines if an action is authorized and provides a reason
func (e *PolicyEvaluator) Evaluate(authCtx AuthContext, permission Permission, resource ResourceContext) (bool, string) {
	// Log the evaluation request
	e.log.Debug("Evaluating authorization",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.String("permission", permission.String()),
		zap.Bool("is_user", authCtx.IsUser()),
		zap.Bool("is_machine", authCtx.IsMachine()),
	)

	// Handle system-level permissions first
	if permission.Resource == "system" {
		return e.evaluateSystemPermission(authCtx, permission)
	}

	// Branch based on context type
	if authCtx.IsMachine() {
		return e.evaluateMachine(authCtx, permission, resource)
	}

	return e.evaluateUser(authCtx, permission, resource)
}

// evaluateSystemPermission evaluates system-level permissions
func (e *PolicyEvaluator) evaluateSystemPermission(authCtx AuthContext, permission Permission) (bool, string) {
	// System permissions are role-based only
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

// evaluateUser evaluates permissions for human users
func (e *PolicyEvaluator) evaluateUser(authCtx AuthContext, permission Permission, resource ResourceContext) (bool, string) {
	// Get roles from AD groups using the group-to-role mapping
	roles := e.getRolesFromGroups(authCtx.GetGroups())

	// PRIORITY 1: Check global role permissions first (global bypass)
	// This allows users with global permissions to access any resource regardless of unit
	for _, role := range roles {
		if e.config.HasRolePermission(role, permission) {
			reason := fmt.Sprintf("user_global_role_bypass_%s", role)
			e.log.Debug("User permission granted via global role bypass",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("permission", permission.String()),
				zap.String("role", role),
				zap.String("reason", reason),
			)
			return true, reason
		}
	}

	// PRIORITY 2: Check unit-based permissions if resource has unitID
	if unitID, ok := resource["unitID"]; ok {
		userUnits := authCtx.GetUnits()
		for _, userUnit := range userUnits {
			if userUnit == unitID {
				// User belongs to the same unit as the resource
				// Check if they have unit-scoped permissions
				for _, role := range roles {
					// Check for unit-scoped role permissions
					if e.hasUnitScopedPermission(role, permission) {
						reason := fmt.Sprintf("user_unit_match_%s", role)
						e.log.Debug("User permission granted via unit match",
							zap.String("identifier", authCtx.GetIdentifier()),
							zap.String("permission", permission.String()),
							zap.String("unit", unitID),
							zap.String("reason", reason),
						)
						return true, reason
					}
				}
			}
		}

		// Resource is unit-scoped but user doesn't have unit access
		reason := fmt.Sprintf("user_unit_mismatch_required_%s", unitID)
		e.log.Debug("User permission denied - unit scope required",
			zap.String("identifier", authCtx.GetIdentifier()),
			zap.String("permission", permission.String()),
			zap.String("required_unit", unitID),
			zap.Strings("user_units", authCtx.GetUnits()),
			zap.String("reason", reason),
		)
		return false, reason
	}

	// PRIORITY 3: For non-unit-scoped resources, we've already checked global permissions above
	// If we get here, the user doesn't have the required permission
	reason := "user_not_authorized"
	e.log.Debug("User permission denied",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.String("permission", permission.String()),
		zap.Strings("roles", roles),
		zap.String("reason", reason),
	)
	return false, reason
}

// evaluateMachine evaluates permissions for service principals
func (e *PolicyEvaluator) evaluateMachine(authCtx AuthContext, permission Permission, resource ResourceContext) (bool, string) {
	// Log incoming resource context for debugging
	resourceKeys := make([]string, 0, len(resource))
	for k := range resource {
		resourceKeys = append(resourceKeys, k)
	}
	e.log.Debug("Evaluator: received resource context",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.Strings("keys", resourceKeys),
		zap.String("machineUnits", resource["machineUnits"]),
		zap.String("unitID", resource["unitID"]))

	// Get roles for the machine
	roles := authCtx.GetRoles()

	// Also check groups for machines (app roles)
	groupRoles := e.getRolesFromGroups(authCtx.GetGroups())

	// PRIORITY 1: Check global role permissions first (global bypass)
	// This allows machines with global permissions to access any resource regardless of unit
	for _, role := range roles {
		if e.config.HasRolePermission(role, permission) {
			reason := fmt.Sprintf("machine_global_role_bypass_%s", role)
			e.log.Debug("Machine permission granted via global role bypass",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("client_id", authCtx.GetClientID()),
				zap.String("permission", permission.String()),
				zap.String("role", role),
				zap.String("reason", reason),
			)
			return true, reason
		}
	}

	for _, role := range groupRoles {
		if e.config.HasRolePermission(role, permission) {
			reason := fmt.Sprintf("machine_global_group_role_bypass_%s", role)
			e.log.Debug("Machine permission granted via global group role bypass",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("client_id", authCtx.GetClientID()),
				zap.String("permission", permission.String()),
				zap.String("role", role),
				zap.String("reason", reason),
			)
			return true, reason
		}
	}

	// PRIORITY 2: Check unit-based permissions if resource has unitID
	if unitID, ok := resource["unitID"]; ok {
		// Get machine units from resource context (populated by MachineUnitResolver)
		machineUnitsVal, existsInMap := resource["machineUnits"]
		e.log.Debug("Checking machineUnits condition",
			zap.Bool("key_exists", existsInMap),
			zap.String("value", machineUnitsVal),
			zap.Bool("value_not_empty", machineUnitsVal != ""),
			zap.String("identifier", authCtx.GetIdentifier()))

		if machineUnitsStr, ok := resource["machineUnits"]; ok && machineUnitsStr != "" {
			e.log.Debug("Inside machineUnits if block",
				zap.String("machineUnitsStr", machineUnitsStr),
				zap.String("identifier", authCtx.GetIdentifier()))
			// Parse comma-separated units
			machineUnits := strings.Split(machineUnitsStr, ",")
			unitMatched := false
			for _, machineUnit := range machineUnits {
				if machineUnit == unitID {
					unitMatched = true
					e.log.Debug("Unit matched! Checking roles for unit-scoped permissions",
						zap.String("identifier", authCtx.GetIdentifier()),
						zap.String("matchedUnit", unitID),
						zap.Strings("roles", roles),
						zap.Strings("groupRoles", groupRoles))
					// Machine is authorized for this unit
					allRoles := append(roles, groupRoles...)
					for _, role := range allRoles {
						hasPermission := e.hasUnitScopedPermission(role, permission)
						e.log.Debug("Checking role for unit-scoped permission",
							zap.String("role", role),
							zap.String("permission", permission.String()),
							zap.Bool("hasPermission", hasPermission))
						if hasPermission {
							reason := fmt.Sprintf("machine_unit_match_%s", role)
							e.log.Debug("Machine permission granted via unit match",
								zap.String("identifier", authCtx.GetIdentifier()),
								zap.String("client_id", authCtx.GetClientID()),
								zap.String("permission", permission.String()),
								zap.String("unit", unitID),
								zap.String("role", role),
								zap.String("reason", reason),
							)
							return true, reason
						}
					}
					e.log.Debug("Unit matched but no role has unit-scoped permission",
						zap.String("identifier", authCtx.GetIdentifier()),
						zap.Strings("allRoles", allRoles),
						zap.String("permission", permission.String()))
				}
			}

			// If machine has units but none matched the resource's unit
			if !unitMatched && len(machineUnits) > 0 {
				reason := fmt.Sprintf("machine_unit_mismatch_required_%s", unitID)
				e.log.Debug("Machine permission denied - unit mismatch",
					zap.String("identifier", authCtx.GetIdentifier()),
					zap.String("client_id", authCtx.GetClientID()),
					zap.String("permission", permission.String()),
					zap.String("required_unit", unitID),
					zap.Strings("machine_units", machineUnits),
					zap.String("reason", reason),
				)
				return false, reason
			}

			// If unit matched but no role granted permission, we should deny here
			if unitMatched {
				reason := fmt.Sprintf("machine_unit_match_no_permission_%s", unitID)
				e.log.Debug("Machine permission denied - unit matched but no role has permission",
					zap.String("identifier", authCtx.GetIdentifier()),
					zap.String("client_id", authCtx.GetClientID()),
					zap.String("permission", permission.String()),
					zap.String("unit", unitID),
					zap.Strings("roles", roles),
					zap.Strings("groupRoles", groupRoles),
					zap.String("reason", reason),
				)
				return false, reason
			}

			// Fall through means machineUnits is empty after split
			e.log.Debug("Machine has machineUnits field but it resulted in empty array after split",
				zap.String("identifier", authCtx.GetIdentifier()),
				zap.String("machineUnitsStr", machineUnitsStr),
				zap.Int("machineUnitsCount", len(machineUnits)))
		}

		// Resource is unit-scoped but no machine units available - deny without checking global permissions
		reason := fmt.Sprintf("machine_unit_required_%s", unitID)
		e.log.Debug("Machine permission denied - unit scope required but no machine units",
			zap.String("identifier", authCtx.GetIdentifier()),
			zap.String("client_id", authCtx.GetClientID()),
			zap.String("permission", permission.String()),
			zap.String("required_unit", unitID),
			zap.String("reason", reason),
		)
		return false, reason
	}

	// PRIORITY 3: For non-unit-scoped resources, we've already checked global permissions above
	// If we get here, the machine doesn't have the required permission

	reason := "machine_not_authorized"
	e.log.Debug("Machine permission denied",
		zap.String("identifier", authCtx.GetIdentifier()),
		zap.String("client_id", authCtx.GetClientID()),
		zap.String("permission", permission.String()),
		zap.Strings("roles", roles),
		zap.String("reason", reason),
	)
	return false, reason
}

// getRoles gets all roles for an auth context
func (e *PolicyEvaluator) getRoles(authCtx AuthContext) []string {
	if authCtx.IsMachine() {
		// For machines, return direct roles plus any mapped from groups
		directRoles := authCtx.GetRoles()
		groupRoles := e.getRolesFromGroups(authCtx.GetGroups())

		// Combine and deduplicate
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

	// For users, map AD groups to roles
	return e.getRolesFromGroups(authCtx.GetGroups())
}

// getRolesFromGroups translates AD groups to internal roles
func (e *PolicyEvaluator) getRolesFromGroups(groups []string) []string {
	return e.config.GetRolesForGroups(groups)
}

// hasUnitScopedPermission checks if a role has unit-scoped permissions
// It delegates to the Config to allow runtime configuration
func (e *PolicyEvaluator) hasUnitScopedPermission(role string, permission Permission) bool {
	return e.config.HasUnitScopedPermission(role, permission)
}
