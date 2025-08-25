package token

import (
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestUnifiedClaims_Validate(t *testing.T) {
	tests := []struct {
		name    string
		claims  UnifiedClaims
		wantErr bool
	}{
		{
			name: "valid with uniqueid",
			claims: UnifiedClaims{
				UniqueID: "123456",
			},
			wantErr: false,
		},
		{
			name: "valid with subject",
			claims: UnifiedClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "user@example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "valid with audience",
			claims: UnifiedClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: []string{"client-123"},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid - no identifiers",
			claims:  UnifiedClaims{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCustomClaimsToUnifiedClaims(t *testing.T) {
	customClaims := CustomClaims{
		Sciper: "123456",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-subject",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	unified := customClaims.ToUnifiedClaims()

	assert.Equal(t, "123456", unified.UniqueID) // Should be mapped from sciper
	assert.Equal(t, "test-subject", unified.Subject)
	assert.Equal(t, customClaims.RegisteredClaims.ExpiresAt, unified.RegisteredClaims.ExpiresAt)
}

func TestUnifiedClaimsToCustomClaims(t *testing.T) {
	unifiedClaims := UnifiedClaims{
		UniqueID: "123456",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-subject",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	custom := unifiedClaims.ToCustomClaims()

	assert.Equal(t, "123456", custom.Sciper) // Should be mapped from UniqueID
	assert.Equal(t, "test-subject", custom.Subject)
	assert.Equal(t, unifiedClaims.RegisteredClaims.ExpiresAt, custom.RegisteredClaims.ExpiresAt)
}

func TestUnifiedClaimsToCustomClaimsFallback(t *testing.T) {
	unifiedClaims := UnifiedClaims{
		UniqueID: "654321",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "test-subject",
		},
	}

	custom := unifiedClaims.ToCustomClaims()

	assert.Equal(t, "654321", custom.Sciper) // Should map UniqueID to Sciper
	assert.Equal(t, "test-subject", custom.Subject)
}

func TestNewUnifiedAndParseUnified(t *testing.T) {
	secret := []byte("test-secret")

	originalClaims := UnifiedClaims{
		UniqueID: "123456",
		Name:     "Test User",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create token
	token := NewUnified(originalClaims)
	tokenString, err := token.Sign(secret)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// Parse token
	parsedClaims, err := ParseUnified(tokenString, secret)
	require.NoError(t, err)
	require.NotNil(t, parsedClaims)

	assert.Equal(t, originalClaims.UniqueID, parsedClaims.UniqueID)
	assert.Equal(t, originalClaims.Name, parsedClaims.Name)
	assert.Equal(t, originalClaims.Subject, parsedClaims.Subject)
}

func TestGenericValidator_DetermineValidationMethod(t *testing.T) {
	logger := zap.NewNop()
	config := Config{
		Method: ValidationHMAC,
		Secret: []byte("test-secret"),
	}

	validator, err := NewGenericValidator(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name     string
		token    *jwt.Token
		expected ValidationMethod
	}{
		{
			name: "HS256 algorithm",
			token: &jwt.Token{
				Header: map[string]interface{}{
					"alg": "HS256",
				},
			},
			expected: ValidationHMAC,
		},
		{
			name: "RS256 algorithm",
			token: &jwt.Token{
				Header: map[string]interface{}{
					"alg": "RS256",
				},
			},
			expected: ValidationJWKS,
		},
		{
			name: "ES256 algorithm",
			token: &jwt.Token{
				Header: map[string]interface{}{
					"alg": "ES256",
				},
			},
			expected: ValidationJWKS,
		},
		{
			name: "unknown algorithm - fall back to config",
			token: &jwt.Token{
				Header: map[string]interface{}{
					"alg": "UNKNOWN",
				},
			},
			expected: ValidationHMAC, // Config default
		},
		{
			name: "no algorithm header - fall back to config",
			token: &jwt.Token{
				Header: map[string]interface{}{},
			},
			expected: ValidationHMAC, // Config default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.determineValidationMethod(tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenericValidator_ValidateToken(t *testing.T) {
	logger := zap.NewNop()
	secret := []byte("test-secret")
	config := Config{
		Method: ValidationHMAC,
		Secret: secret,
	}

	validator, err := NewGenericValidator(config, logger)
	require.NoError(t, err)

	// Create a valid HMAC token
	originalClaims := UnifiedClaims{
		UniqueID: "123456",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := NewUnified(originalClaims)
	tokenString, err := token.Sign(secret)
	require.NoError(t, err)

	// Validate the token
	claims, err := validator.ValidateToken(tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, originalClaims.UniqueID, claims.UniqueID)
	assert.Equal(t, originalClaims.Subject, claims.Subject)
}

func TestGetUserIDAndPersonService(t *testing.T) {
	tests := []struct {
		name              string
		claims            *UnifiedClaims
		expectedID        string
		expectedIsPerson  bool
		expectedIsService bool
	}{
		{
			name: "person with 6-digit SCIPER",
			claims: &UnifiedClaims{
				UniqueID: "123456",
			},
			expectedID:        "123456",
			expectedIsPerson:  true,
			expectedIsService: false,
		},
		{
			name: "service with M+5digits pattern",
			claims: &UnifiedClaims{
				UniqueID: "M02575",
			},
			expectedID:        "M02575",
			expectedIsPerson:  false,
			expectedIsService: true,
		},
		{
			name: "service with M+5digits pattern (different number)",
			claims: &UnifiedClaims{
				UniqueID: "M12345",
			},
			expectedID:        "M12345",
			expectedIsPerson:  false,
			expectedIsService: true,
		},
		{
			name: "unknown type - no uniqueid, fallback to subject",
			claims: &UnifiedClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "my-service@example.com",
				},
			},
			expectedID:        "my-service@example.com",
			expectedIsPerson:  false,
			expectedIsService: false, // No UniqueID so not a service account
		},
		{
			name: "unknown type - fallback to audience",
			claims: &UnifiedClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: []string{"client-123", "other"},
				},
			},
			expectedID:        "client-123",
			expectedIsPerson:  false,
			expectedIsService: false, // No UniqueID so not a service account
		},
		{
			name: "unknown type - non-standard uniqueid pattern",
			claims: &UnifiedClaims{
				UniqueID: "client-abc123",
			},
			expectedID:        "client-abc123",
			expectedIsPerson:  false,
			expectedIsService: false, // Doesn't match M+5digits pattern
		},
		{
			name: "unknown type - 5-digit uniqueid (not SCIPER or service)",
			claims: &UnifiedClaims{
				UniqueID: "12345",
			},
			expectedID:        "12345",
			expectedIsPerson:  false,
			expectedIsService: false, // 5 digits but no M prefix
		},
		{
			name: "unknown type - invalid service pattern (M+4digits)",
			claims: &UnifiedClaims{
				UniqueID: "M1234",
			},
			expectedID:        "M1234",
			expectedIsPerson:  false,
			expectedIsService: false, // Only 4 digits after M
		},
		{
			name: "unknown type - invalid service pattern (M+6digits)",
			claims: &UnifiedClaims{
				UniqueID: "M123456",
			},
			expectedID:        "M123456",
			expectedIsPerson:  false,
			expectedIsService: false, // 6 digits after M (too many)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID := GetUserID(tt.claims)
			isPerson := IsPerson(tt.claims)
			isService := IsService(tt.claims)

			assert.Equal(t, tt.expectedID, userID)
			assert.Equal(t, tt.expectedIsPerson, isPerson)
			assert.Equal(t, tt.expectedIsService, isService)
		})
	}
}
