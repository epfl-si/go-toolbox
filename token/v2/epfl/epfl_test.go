package epfl_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/epfl-si/go-toolbox/token/v2"
	"github.com/epfl-si/go-toolbox/token/v2/epfl"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestIsPerson(t *testing.T) {
	tests := []struct {
		name     string
		claims   *token.UnifiedClaims
		expected bool
	}{
		{
			name: "valid SCIPER",
			claims: &token.UnifiedClaims{
				UniqueID: "123456",
			},
			expected: true,
		},
		{
			name: "service account",
			claims: &token.UnifiedClaims{
				UniqueID: "M02575",
			},
			expected: false,
		},
		{
			name: "empty uniqueid",
			claims: &token.UnifiedClaims{
				UniqueID: "",
			},
			expected: false,
		},
		{
			name: "invalid format",
			claims: &token.UnifiedClaims{
				UniqueID: "ABC123",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := epfl.IsPerson(tt.claims)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsService(t *testing.T) {
	tests := []struct {
		name     string
		claims   *token.UnifiedClaims
		expected bool
	}{
		{
			name: "valid service account",
			claims: &token.UnifiedClaims{
				UniqueID: "M02575",
			},
			expected: true,
		},
		{
			name: "person SCIPER",
			claims: &token.UnifiedClaims{
				UniqueID: "123456",
			},
			expected: false,
		},
		{
			name: "invalid service format",
			claims: &token.UnifiedClaims{
				UniqueID: "M1234", // Only 4 digits
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := epfl.IsService(tt.claims)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetUserType(t *testing.T) {
	tests := []struct {
		name     string
		claims   *token.UnifiedClaims
		expected string
	}{
		{
			name: "person",
			claims: &token.UnifiedClaims{
				UniqueID: "123456",
			},
			expected: epfl.UserTypePerson,
		},
		{
			name: "service",
			claims: &token.UnifiedClaims{
				UniqueID: "M02575",
			},
			expected: epfl.UserTypeService,
		},
		{
			name: "unknown",
			claims: &token.UnifiedClaims{
				UniqueID: "invalid",
			},
			expected: epfl.UserTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := epfl.GetUserType(tt.claims)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateUniqueID(t *testing.T) {
	tests := []struct {
		name     string
		uniqueID string
		wantErr  bool
	}{
		{
			name:     "valid SCIPER",
			uniqueID: "123456",
			wantErr:  false,
		},
		{
			name:     "valid service account",
			uniqueID: "M02575",
			wantErr:  false,
		},
		{
			name:     "empty is valid",
			uniqueID: "",
			wantErr:  false,
		},
		{
			name:     "invalid format",
			uniqueID: "12345",
			wantErr:  true,
		},
		{
			name:     "invalid service format",
			uniqueID: "M123456",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := epfl.ValidateUniqueID(tt.uniqueID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewConfig(t *testing.T) {
	baseConfig := token.Config{
		Method: token.SigningHMAC,
		Secret: []byte("test-secret"),
	}

	// Test with empty issuer
	config := epfl.NewConfig(baseConfig)
	assert.Equal(t, "https://login.microsoftonline.com/c9df4995-1d69-4ba3-a0a6-71411d6e2e79/v2.0", config.RequiredIssuer)
	assert.Equal(t, []string{"RS256", "HS256"}, config.AllowedAlgorithms)

	// Test with existing issuer (should not be overwritten)
	baseConfig.RequiredIssuer = "custom-issuer"
	config = epfl.NewConfig(baseConfig)
	assert.Equal(t, "custom-issuer", config.RequiredIssuer)

	// Test with existing algorithms (should not be overwritten)
	baseConfig.AllowedAlgorithms = []string{"HS512"}
	config = epfl.NewConfig(baseConfig)
	assert.Equal(t, []string{"HS512"}, config.AllowedAlgorithms)
}

func Example() {
	logger := zap.NewNop()
	secret := []byte("test-secret")

	// Create a generic validator without issuer requirement for example
	config := token.Config{
		Method: token.SigningHMAC,
		Secret: secret,
	}

	validator, _ := token.NewGenericValidator(config, logger)

	// Create a token with EPFL-specific data
	claims := token.UnifiedClaims{
		UniqueID: "123456", // SCIPER
		Name:     "Test User",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test.user@epfl.ch",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	tokenString, _ := token.SignUnified(claims, secret)

	// Validate token
	validatedClaims, err := validator.ValidateToken(tokenString)
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	// Use EPFL-specific functions
	fmt.Printf("Is Person: %t\n", epfl.IsPerson(validatedClaims))
	fmt.Printf("User Type: %s\n", epfl.GetUserType(validatedClaims))

	// Output:
	// Is Person: true
	// User Type: person
}

func TestEPFLIntegration(t *testing.T) {
	logger := zap.NewNop()
	secret := []byte("test-secret")

	// Create validator without issuer requirement for tests
	config := token.Config{
		Method: token.SigningHMAC,
		Secret: secret,
	}

	validator, err := token.NewGenericValidator(config, logger)
	require.NoError(t, err)

	// Test with person token
	t.Run("person token", func(t *testing.T) {
		claims := token.UnifiedClaims{
			UniqueID: "654321",
			Name:     "John Doe",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "john.doe@epfl.ch",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		tokenString, err := token.SignUnified(claims, secret)
		require.NoError(t, err)

		validatedClaims, err := validator.ValidateToken(tokenString)
		require.NoError(t, err)

		assert.True(t, epfl.IsPerson(validatedClaims))
		assert.False(t, epfl.IsService(validatedClaims))
		assert.Equal(t, epfl.UserTypePerson, epfl.GetUserType(validatedClaims))
	})

	// Test with service account token
	t.Run("service account token", func(t *testing.T) {
		claims := token.UnifiedClaims{
			UniqueID: "M02575",
			Name:     "Service Account",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "service@epfl.ch",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		tokenString, err := token.SignUnified(claims, secret)
		require.NoError(t, err)

		validatedClaims, err := validator.ValidateToken(tokenString)
		require.NoError(t, err)

		assert.False(t, epfl.IsPerson(validatedClaims))
		assert.True(t, epfl.IsService(validatedClaims))
		assert.Equal(t, epfl.UserTypeService, epfl.GetUserType(validatedClaims))
	})
}
