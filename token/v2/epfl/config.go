package epfl

import (
	"github.com/epfl-si/go-toolbox/token/v2"
)

// NewConfig creates a token.Config with EPFL-specific defaults
func NewConfig(baseConfig token.Config) token.Config {
	// Set EPFL-specific defaults
	if baseConfig.RequiredIssuer == "" {
		// EPFL's Azure AD tenant ID
		baseConfig.RequiredIssuer = "https://login.microsoftonline.com/c9df4995-1d69-4ba3-a0a6-71411d6e2e79/v2.0"
	}

	// Add EPFL's default allowed algorithms if none specified
	if len(baseConfig.AllowedAlgorithms) == 0 {
		baseConfig.AllowedAlgorithms = []string{"RS256", "HS256"}
	}

	return baseConfig
}
