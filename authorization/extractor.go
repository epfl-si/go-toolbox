package authorization

import (
	"context"
	"errors"
	"slices"

	tokenV2 "github.com/epfl-si/go-toolbox/token/v2"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// UnitsResolver fetches unit IDs for a user when the token doesn't carry them.
type UnitsResolver func(ctx context.Context, userID string) ([]string, error)

// RolesAugmenter augments roles from an external source (DB, gRPC, cache).
type RolesAugmenter func(ctx context.Context, userID string, derivedRoles []string) ([]string, error)

// ExtractorOptions controls the DefaultExtractor behavior.
type ExtractorOptions struct {
	Config         *Config
	UnitsResolver  UnitsResolver
	RolesAugmenter RolesAugmenter
	Log            *zap.Logger
}

// DefaultExtractor returns a gin middleware that builds an AuthContext from
// UnifiedClaims and stores it via SetAuthContext. It handles user and machine
// tokens, applies Config.DefaultUserRoles, and optionally augments units/roles
// via callbacks.
func DefaultExtractor(opts ExtractorOptions) gin.HandlerFunc {
	if opts.Log == nil {
		opts.Log = zap.NewNop()
	}
	return func(c *gin.Context) {
		if c.Request.Method == "OPTIONS" {
			return
		}
		if existing, err := GetAuthContext(c); err == nil && existing != nil {
			c.Next()
			return
		}
		claims, ok := tokenV2.GetClaims(c)
		if !ok {
			c.Next()
			return
		}
		authCtx, err := buildAuthContext(c.Request.Context(), claims, opts)
		if err != nil {
			opts.Log.Debug("auth context build failed", zap.Error(err))
			c.Next()
			return
		}
		SetAuthContext(c, authCtx)
		opts.Log.Debug("auth context set",
			zap.String("identifier", authCtx.GetIdentifier()),
			zap.Bool("is_user", authCtx.IsUser()),
			zap.Bool("is_machine", authCtx.IsMachine()),
		)
		c.Next()
	}
}

func buildAuthContext(ctx context.Context, claims *tokenV2.UnifiedClaims, opts ExtractorOptions) (AuthContext, error) {
	if claims == nil {
		return nil, errors.New("nil claims")
	}

	if tokenV2.GetTokenType(claims) == tokenV2.TypeMachine {
		appID := tokenV2.GetApplicationID(claims)
		var units []string
		if opts.Config != nil {
			units = opts.Config.MachineUnits[appID]
		}
		return &MachineAuthContext{
			ServicePrincipalID: claims.Subject,
			ClientID:           appID,
			Groups:             claims.Groups,
			Roles:              claims.Roles,
			AllowedUnits:       units,
		}, nil
	}

	// User token
	units := make([]string, 0, len(claims.Units))
	for _, u := range claims.Units {
		units = append(units, u.ID)
	}
	if len(units) == 0 && opts.UnitsResolver != nil {
		if fetched, err := opts.UnitsResolver(ctx, claims.UniqueID); err == nil {
			units = fetched
		}
	}

	var roles []string
	if opts.Config != nil {
		roles = opts.Config.GetRolesForGroups(claims.Groups)
		for _, r := range opts.Config.DefaultUserRoles {
			if !slices.Contains(roles, r) {
				roles = append(roles, r)
			}
		}
	}
	if opts.RolesAugmenter != nil {
		if augmented, err := opts.RolesAugmenter(ctx, claims.UniqueID, roles); err == nil {
			roles = augmented
		}
	}

	return &UserAuthContext{
		UniqueID: claims.UniqueID,
		Groups:   claims.Groups,
		Units:    units,
		Roles:    roles,
	}, nil
}
