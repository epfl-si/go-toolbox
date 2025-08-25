package token

import (
	"net/http"
	"net/http/httptest"
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

func TestJWKSValidator_URLConstruction(t *testing.T) {
	// Mock JWKS server that expects no query parameters
	jwksResponse := `{
		"keys": [
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "test-key-id",
				"x5t": "test-key-id",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB"
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that no appid query parameter is present
		if appid := r.URL.Query().Get("appid"); appid != "" {
			t.Errorf("Unexpected appid query parameter: %s", appid)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_request","error_description":"Unexpected appid parameter"}`))
			return
		}

		// Expected path format: /tenant-id/discovery/v2.0/keys
		expectedPath := "/b6cddbc1-2348-4644-af0a-2fdb55573e3b/discovery/v2.0/keys"
		if r.URL.Path != expectedPath {
			t.Errorf("Unexpected path: %s, expected: %s", r.URL.Path, expectedPath)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(jwksResponse))
	}))
	defer server.Close()

	logger := zap.NewNop()
	tenantID := "b6cddbc1-2348-4644-af0a-2fdb55573e3b"

	// Create validator with mock server URL
	validator := NewJWKSValidator(server.URL, tenantID, time.Hour, logger)

	// Create a test token with RSA256 algorithm and proper claims
	// This token will fail signature validation but should pass URL construction test
	testToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJhdWQiOiJhcGk6Ly90ZXN0LWFwcCIsImlzcyI6Imh0dHBzOi8vdGVzdCIsInRpZCI6ImI2Y2RkYmMxLTIzNDgtNDY0NC1hZjBhLTJmZGI1NTU3M2UzYiIsInN1YiI6InRlc3QtdXNlciIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNjAwMDAwMDAwLCJuYmYiOjE2MDAwMDAwMDB9.invalid-signature"

	// This should fail with signature error, not URL construction error
	_, err := validator.ValidateToken(testToken)

	// The error should be about signature validation or token malformation, not JWKS fetching
	// This proves the URL construction worked (server was called successfully)
	assert.Error(t, err)

	// Any of these errors indicate that JWKS was successfully fetched but validation failed
	validationErrors := []string{
		"JWKS validation failed",
		"token is malformed",
		"could not base64 decode signature",
		"invalid signature",
		"failed to parse JWKS",
	}

	hasValidationError := false
	for _, validErr := range validationErrors {
		if err != nil && (err.Error() == validErr ||
			err.Error() == "JWKS validation failed: "+validErr ||
			(validErr == "token is malformed" && err.Error() == "JWKS validation failed: token is malformed: could not base64 decode signature: illegal base64 data at input byte 16")) {
			hasValidationError = true
			break
		}
	}

	assert.True(t, hasValidationError, "Error should indicate validation failure, not URL fetching failure. Got: %s", err.Error())

	// Most importantly, these errors should NOT appear (they indicate URL construction problems)
	assert.NotContains(t, err.Error(), "failed to fetch JWKS")
	assert.NotContains(t, err.Error(), "400")
	assert.NotContains(t, err.Error(), "invalid_request")
}

func TestJWKSValidator_RealMicrosoftEntraToken(t *testing.T) {
	// Skip if SLOW_TESTS is not set
	if os.Getenv("SLOW_TESTS") != "1" {
		t.Skip("Skipping slow test that requires database. Set SLOW_TESTS=1 to run")
	}

	// Real Microsoft Entra ID token (expires 2025-08-25T17:06:07+02:00)
	// This is the same token from the original request
	tokenString := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSIsImtpZCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSJ9.eyJhdWQiOiJhcGk6Ly9jZTMwNmY0Zi02M2VhLTRhZTMtOThjZS0xZGJhNzU3MmU5OTAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9iNmNkZGJjMS0yMzQ4LTQ2NDQtYWYwYS0yZmRiNTU1NzNlM2IvIiwiaWF0IjoxNzU2MTMwNDY3LCJuYmYiOjE3NTYxMzA0NjcsImV4cCI6MTc1NjEzNDM2NywiYWlvIjoiQVNRQTIvOFpBQUFBbUpTTDBNd0RRTTgyaVlNU0pVS0tQMWZjL3dqWWtCSHF5bTZWNXI0cnJwND0iLCJhcHBpZCI6ImNlMzA2ZjRmLTYzZWEtNGFlMy05OGNlLTFkYmE3NTcyZTk5MCIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2I2Y2RkYmMxLTIzNDgtNDY0NC1hZjBhLTJmZGI1NTU3M2UzYi8iLCJvaWQiOiI0Y2Y5YjRkMS00YjMwLTQ4ZTQtOThkOC04YzNiMDJjMWUyYTMiLCJyaCI6IjEuQVVnQXdkdk50a2dqUkVhdkNpX2JWVmMtTzA5dk1NN3FZLU5LbU00ZHVuVnk2WkEyQVFCSUFBLiIsInN1YiI6IjRjZjliNGQxLTRiMzAtNDhlNC05OGQ4LThjM2IwMmMxZTJhMyIsInRpZCI6ImI2Y2RkYmMxLTIzNDgtNDY0NC1hZjBhLTJmZGI1NTU3M2UzYiIsInV0aSI6IlFHWWEyWFF2UEVxdmp5OG1VYWtPQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfZnRkIjoiUVpnTzkwR3k0Y3NncW01eUFpVEhIWWxWQW5LMTIyUnl2ZkFHNXZ5OWhpOEJaWFZ5YjNCbGQyVnpkQzFrYzIxeiJ9.TxR2e-TM04fRC8yxm6_nMIVnmkV1mY5ua6nWWRb41SAmclxqVCBEK9s9OAmrQLe-rIYE1hK9qYBkxR7cntUHhF6IyxqpamR9_g_PbZnMdnv44A1eI_ngusatWsGYGJnVvvJAqxO1NtDyH6knTQQfDJTOHz890KGaKmRY15MXtdgzZl1d3ujbrN3QPpMswHsFr6HBFFtYGWK-j7erWcDlbdYP13rpduywVTBwAuEqEWwaCnfWdwHUpQeiysBhChU4KwIWkmuPYYA_CTaWKVvNhTZ9EZ9BVf7C8jdmYfcnzVzO0eNF_mPek2fSq-OK4g0B29S2mmHXR4XfnKhdobz66A"

	logger := zap.NewNop()

	// Test with JWKSValidator
	t.Run("JWKSValidator", func(t *testing.T) {
		validator := NewJWKSValidator(
			"https://login.microsoftonline.com",
			"", // Let it extract tenant from token
			24*time.Hour,
			logger,
		)

		claims, err := validator.ValidateToken(tokenString)

		// Check if token is expired
		if err != nil && err.Error() == "token has expired" {
			t.Skip("Token has expired, skipping validation test")
		}

		require.NoError(t, err, "JWKS validation should succeed with fixed URL construction")
		require.NotNil(t, claims)

		// Verify expected claims from the token
		assert.Equal(t, "4cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a3", claims.Subject)
		assert.Equal(t, "https://sts.windows.net/b6cddbc1-2348-4644-af0a-2fdb55573e3b/", claims.Issuer)
		assert.Equal(t, "b6cddbc1-2348-4644-af0a-2fdb55573e3b", claims.TenantID)
		expectedAud := []string{"api://ce306f4f-63ea-4ae3-98ce-1dba7572e990"}
		assert.Equal(t, expectedAud, []string(claims.Audience))

		// Verify user classification
		assert.Equal(t, "4cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a3", GetUserID(claims))
		assert.Equal(t, "unknown", GetUserType(claims)) // No SCIPER
		assert.False(t, IsPerson(claims))
		assert.False(t, IsService(claims))
	})

	// Test with GenericValidator
	t.Run("GenericValidator", func(t *testing.T) {
		config := Config{
			Method: ValidationJWKS,
			JWKSConfig: &JWKSConfig{
				BaseURL:     "https://login.microsoftonline.com",
				KeyCacheTTL: 24 * time.Hour,
			},
		}

		validator, err := NewGenericValidator(config, logger)
		require.NoError(t, err)

		claims, err := validator.ValidateToken(tokenString)

		// Check if token is expired
		if err != nil && err.Error() == "token has expired" {
			t.Skip("Token has expired, skipping validation test")
		}

		require.NoError(t, err, "Generic validator should succeed with fixed URL construction")
		require.NotNil(t, claims)

		// Verify same claims as above
		assert.Equal(t, "4cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a3", claims.Subject)
		assert.Equal(t, "b6cddbc1-2348-4644-af0a-2fdb55573e3b", claims.TenantID)
	})
}

func TestJWKSValidator_ErrorHandling(t *testing.T) {
	logger := zap.NewNop()

	t.Run("invalid token format", func(t *testing.T) {
		validator := NewJWKSValidator("https://login.microsoftonline.com", "", time.Hour, logger)

		_, err := validator.ValidateToken("invalid-token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse token header")
	})

	t.Run("HMAC token with JWKS validator should fail", func(t *testing.T) {
		validator := NewJWKSValidator("https://login.microsoftonline.com", "", time.Hour, logger)

		// Create HMAC token
		claims := UnifiedClaims{
			UniqueID: "123456",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "test-user",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		token := NewUnified(claims)
		tokenString, err := token.Sign([]byte("secret"))
		require.NoError(t, err)

		_, err = validator.ValidateToken(tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
		assert.Contains(t, err.Error(), "HS256")
	})
}
