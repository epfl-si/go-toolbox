package token

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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

func TestSignUnifiedAndParseUnifiedHMAC(t *testing.T) {
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

	// Create token using clean API
	tokenString, err := SignUnified(originalClaims, secret)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// Parse token using clean API
	parsedClaims, err := ParseUnifiedHMAC(tokenString, secret)
	require.NoError(t, err)
	require.NotNil(t, parsedClaims)

	assert.Equal(t, originalClaims.UniqueID, parsedClaims.UniqueID)
	assert.Equal(t, originalClaims.Name, parsedClaims.Name)
	assert.Equal(t, originalClaims.Subject, parsedClaims.Subject)
}

func TestGenericValidator_DetermineSigningMethod(t *testing.T) {
	logger := zap.NewNop()
	config := Config{
		Method: SigningHMAC,
		Secret: []byte("test-secret"),
	}

	validator, err := NewGenericValidator(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name     string
		token    *jwt.Token
		expected SigningMethod
	}{
		{
			name: "HS256 algorithm",
			token: &jwt.Token{
				Header: map[string]interface{}{
					"alg": "HS256",
				},
			},
			expected: SigningHMAC,
		},
		{
			name: "RS256 algorithm",
			token: &jwt.Token{
				Header: map[string]interface{}{
					"alg": "RS256",
				},
			},
			expected: SigningPublicKey,
		},
		{
			name: "ES256 algorithm",
			token: &jwt.Token{
				Header: map[string]interface{}{
					"alg": "ES256",
				},
			},
			expected: SigningPublicKey,
		},
		{
			name: "unknown algorithm - fall back to config",
			token: &jwt.Token{
				Header: map[string]interface{}{
					"alg": "UNKNOWN",
				},
			},
			expected: SigningHMAC, // Config default
		},
		{
			name: "no algorithm header - fall back to config",
			token: &jwt.Token{
				Header: map[string]interface{}{},
			},
			expected: SigningHMAC, // Config default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.determineSigningMethod(tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenericValidator_ValidateToken(t *testing.T) {
	logger := zap.NewNop()
	secret := []byte("test-secret")
	config := Config{
		Method: SigningHMAC,
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

	tokenString, err := SignUnified(originalClaims, secret)
	require.NoError(t, err)

	// Validate the token
	claims, err := validator.ValidateToken(tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, originalClaims.UniqueID, claims.UniqueID)
	assert.Equal(t, originalClaims.Subject, claims.Subject)
}

func TestGetPrincipalIDAndPersonService(t *testing.T) {
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
			principalID := GetPrincipalID(tt.claims)
			// Note: IsPerson and IsService checks moved to epfl package

			assert.Equal(t, tt.expectedID, principalID)
			// EPFL-specific type checks removed from core tests
		})
	}
}

// Tests for machine token functionality
func TestGetTokenType_MachineTokens(t *testing.T) {
	tests := []struct {
		name         string
		claims       *UnifiedClaims
		expectedType Type
	}{
		{
			name: "machine token with azp and roles",
			claims: &UnifiedClaims{
				// TODO: Uncomment values and verify correctness
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				Roles:           []string{"api.read", "api.write"},
			},
			expectedType: TypeMachine,
		},
		{
			name: "machine token with appid and roles (v1 token)",
			claims: &UnifiedClaims{
				// TODO: Uncomment values and verify correctness
				AppID: "ce306f4f-63ea-4ae3-98ce-1dba7572e990", // Valid Azure AD App ID (UUID)
				Roles: []string{"api.admin"},
			},
			expectedType: TypeMachine,
		},
		{
			name: "service account is user token (not machine)",
			claims: &UnifiedClaims{
				UniqueID: "M02575", // Service account identifier - should be TypeUser
			},
			expectedType: TypeUser, // FIXED: Service accounts are user tokens, not machine tokens
		},
		{
			name: "user token with azp but also has name",
			claims: &UnifiedClaims{
				// TODO: Uncomment values and verify correctness
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				Roles:           []string{"user.role"},
				Name:            "John Doe", // TODO: Verify name contains real-world example
			},
			expectedType: TypeUser, // Name indicates user token
		},
		{
			name: "user token with SCIPER",
			claims: &UnifiedClaims{
				// TODO: Uncomment values and verify correctness
				UniqueID: "123456", // TODO: Verify SCIPER pattern
			},
			expectedType: TypeUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenType := GetTokenType(tt.claims)
			assert.Equal(t, tt.expectedType, tokenType)
		})
	}
}

func TestGetApplicationID(t *testing.T) {
	tests := []struct {
		name     string
		claims   *UnifiedClaims
		expected string
	}{
		{
			name: "v2 token with azp",
			claims: &UnifiedClaims{
				AuthorizedParty: "5cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a4", // Valid Azure AD App ID (UUID)
			},
			expected: "5cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a4",
		},
		{
			name: "v1 token with appid",
			claims: &UnifiedClaims{
				AppID: "6cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a5", // Valid Azure AD App ID (UUID)
			},
			expected: "6cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a5",
		},
		{
			name: "both azp and appid (azp takes priority)",
			claims: &UnifiedClaims{
				AuthorizedParty: "5cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a4", // Valid Azure AD App ID (UUID)
				AppID:           "6cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a5", // Valid Azure AD App ID (UUID)
			},
			expected: "5cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a4",
		},
		{
			name:     "neither azp nor appid",
			claims:   &UnifiedClaims{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appID := GetApplicationID(tt.claims)
			assert.Equal(t, tt.expected, appID)
		})
	}
}

func TestGetServicePrincipalID(t *testing.T) {
	tests := []struct {
		name     string
		claims   *UnifiedClaims
		expected string
	}{
		{
			name: "oid present",
			claims: &UnifiedClaims{
				ObjectID:        "7cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a6", // TODO: Verify object ID format
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
			},
			expected: "7cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a6",
		},
		{
			name: "no oid, fallback to azp",
			claims: &UnifiedClaims{
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
			},
			expected: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7",
		},
		{
			name: "no oid, fallback to appid",
			claims: &UnifiedClaims{
				AppID: "ce306f4f-63ea-4ae3-98ce-1dba7572e990", // Valid Azure AD App ID (UUID)
			},
			expected: "ce306f4f-63ea-4ae3-98ce-1dba7572e990",
		},
		{
			name:     "no identifiers",
			claims:   &UnifiedClaims{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spID := GetServicePrincipalID(tt.claims)
			assert.Equal(t, tt.expected, spID)
		})
	}
}

func TestHasApplicationRole(t *testing.T) {
	tests := []struct {
		name     string
		claims   *UnifiedClaims
		role     string
		expected bool
	}{
		{
			name: "machine token with role",
			claims: &UnifiedClaims{
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				Roles:           []string{"api.read", "api.write"},
			},
			role:     "api.read",
			expected: true,
		},
		{
			name: "machine token without role",
			claims: &UnifiedClaims{
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				Roles:           []string{"api.read"},
			},
			role:     "api.write",
			expected: false,
		},
		{
			name: "user token with role (should return false)",
			claims: &UnifiedClaims{
				UniqueID: "123456",
				Roles:    []string{"user.role"},
			},
			role:     "user.role",
			expected: false, // Not a machine token
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasRole := HasApplicationRole(tt.claims, tt.role)
			assert.Equal(t, tt.expected, hasRole)
		})
	}
}

func TestExtractMachineContext(t *testing.T) {
	tests := []struct {
		name     string
		claims   *UnifiedClaims
		expected *MachineContext
	}{
		{
			name: "valid machine token",
			claims: &UnifiedClaims{
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				ObjectID:        "7cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a6", // TODO: Verify object ID format
				Roles:           []string{"api.read", "api.write"},
			},
			expected: &MachineContext{
				ApplicationID:      "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7",
				ServicePrincipalID: "7cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a6",
				Roles:              []string{"api.read", "api.write"},
				Identity:           "Application:8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7",
			},
		},
		{
			name: "service account returns nil (not machine token)",
			claims: &UnifiedClaims{
				UniqueID: "M02575", // Service account - should be TypeUser, not TypeMachine
			},
			expected: nil,
		},
		{
			name: "user token returns nil",
			claims: &UnifiedClaims{
				UniqueID: "123456",
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ExtractMachineContext(tt.claims)
			if tt.expected == nil {
				assert.Nil(t, ctx)
			} else {
				require.NotNil(t, ctx)
				assert.Equal(t, tt.expected.ApplicationID, ctx.ApplicationID)
				assert.Equal(t, tt.expected.ServicePrincipalID, ctx.ServicePrincipalID)
				assert.Equal(t, tt.expected.Roles, ctx.Roles)
				assert.Equal(t, tt.expected.Identity, ctx.Identity)
			}
		})
	}
}

func TestGetIdentity_MachineTokens(t *testing.T) {
	tests := []struct {
		name     string
		claims   *UnifiedClaims
		expected string
	}{
		{
			name: "application token",
			claims: &UnifiedClaims{
				// TODO: Uncomment values and verify correctness
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				Roles:           []string{"api.read"},
			},
			expected: "Application:8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7",
		},
		{
			name: "service principal with oid",
			claims: &UnifiedClaims{
				// TODO: Uncomment values and verify correctness
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				ObjectID:        "sp-object-67890",                      // TODO: Verify object ID format
				Roles:           []string{"api.read"},
			},
			expected: "Application:8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // AppID takes priority
		},
		{
			name: "service account",
			claims: &UnifiedClaims{
				// TODO: Uncomment values and verify correctness
				UniqueID: "M02575", // TODO: Verify service account identifier
			},
			expected: "User:M02575", // After separation, service accounts are just users in core
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := GetIdentity(tt.claims)
			assert.Equal(t, tt.expected, identity)
		})
	}
}

func TestNewMachineTokenForTesting(t *testing.T) {
	secret := []byte("test-secret")
	appID := "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7"
	roles := []string{"api.read", "api.write"}

	// TODO: Uncomment values and verify correctness
	tokenString, err := NewMachineTokenForTesting(appID, roles, secret)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// Validate the token can be parsed
	claims, err := ParseUnifiedHMAC(tokenString, secret)
	require.NoError(t, err)
	require.NotNil(t, claims)

	// Verify token structure
	assert.Equal(t, appID, claims.AuthorizedParty)
	assert.Equal(t, roles, claims.Roles)
	assert.Equal(t, TypeMachine, GetTokenType(claims))
	assert.True(t, IsMachineToken(claims))
	assert.Equal(t, appID, GetApplicationID(claims))
	assert.Contains(t, GetServicePrincipalID(claims), appID)
}

// Middleware integration tests
func TestUnifiedJWTMiddleware_MachineContext(t *testing.T) {
	logger := zap.NewNop()
	secret := []byte("test-secret")

	// Create validator
	validator := NewHMACValidator(secret, logger, Config{})
	config := DefaultMiddlewareConfig(validator, logger)

	// Create test router
	router := gin.New()
	router.Use(UnifiedJWTMiddleware(config))
	router.GET("/test", func(c *gin.Context) {
		// TODO: Verify context extraction
		machineCtx, machineCtxExists := c.Get("machine_context")
		userCtx, userCtxExists := c.Get("user_context")

		// Convert to map for easier assertion
		var machineCtxMap map[string]interface{}
		var userCtxMap map[string]interface{}

		if machineCtxExists {
			machineCtxMap = map[string]interface{}{
				"app_id":   machineCtx.(*MachineContext).ApplicationID,
				"roles":    machineCtx.(*MachineContext).Roles,
				"identity": machineCtx.(*MachineContext).Identity,
			}
		}

		if userCtxExists {
			if userCtxStruct, ok := userCtx.(*UserContext); ok {
				userCtxMap = map[string]interface{}{
					"id":    userCtxStruct.ID,
					"type":  userCtxStruct.Type,
					"email": userCtxStruct.Email,
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"machine_context": machineCtxMap,
			"user_context":    userCtxMap,
		})
	})

	tests := []struct {
		name                string
		tokenClaims         UnifiedClaims
		expectMachineCtx    bool
		expectUserCtx       bool
		expectedAppID       string
		expectedPrincipalID string
	}{
		{
			name: "machine token sets machine_context",
			tokenClaims: UnifiedClaims{
				// TODO: Uncomment and verify token structure
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				ObjectID:        "7cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a6", // TODO: Verify object ID format
				Roles:           []string{"api.read"},
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "app:8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // TODO: Verify subject format
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			expectMachineCtx: true,
			expectUserCtx:    false,
			expectedAppID:    "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7",
		},
		{
			name: "user token sets user_context",
			tokenClaims: UnifiedClaims{
				// TODO: Uncomment and verify token structure
				UniqueID: "123456",           // TODO: Verify user ID format
				Name:     "Test User",        // TODO: Verify name format
				Email:    "test@example.com", // TODO: Verify email format
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "user:123456", // TODO: Verify subject format
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			expectMachineCtx:    false,
			expectUserCtx:       true,
			expectedPrincipalID: "123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create token using clean API
			tokenString, err := SignUnified(tt.tokenClaims, secret)
			require.NoError(t, err)

			// Make request
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)
			w := httptest.NewRecorder()

			// Process request
			router.ServeHTTP(w, req)

			// Verify response
			assert.Equal(t, http.StatusOK, w.Code)

			// Parse response JSON
			var responseBody map[string]interface{}
			err = json.NewDecoder(w.Body).Decode(&responseBody)
			require.NoError(t, err)

			// Verify machine context
			if tt.expectMachineCtx {
				machineCtx, ok := responseBody["machine_context"].(map[string]interface{})
				require.True(t, ok, "machine context not set")
				assert.Equal(t, tt.expectedAppID, machineCtx["app_id"])
				assert.Contains(t, machineCtx, "identity")
				assert.Contains(t, machineCtx, "roles")
			} else {
				assert.Nil(t, responseBody["machine_context"])
			}

			// Verify user context
			if tt.expectUserCtx {
				userCtx, ok := responseBody["user_context"].(map[string]interface{})
				require.True(t, ok, "user context not set")
				assert.Equal(t, tt.expectedPrincipalID, userCtx["id"])
			} else {
				assert.Nil(t, responseBody["user_context"])
			}
		})
	}
}

func TestMachineTokenMiddleware(t *testing.T) {
	logger := zap.NewNop()
	secret := []byte("test-secret")

	// Create validator
	validator := NewHMACValidator(secret, logger, Config{})

	// Create test router with machine middleware
	router := gin.New()
	router.Use(MachineTokenMiddleware(validator, logger))
	router.GET("/m2m-endpoint", func(c *gin.Context) {
		// TODO: Verify machine context extraction
		machineCtx, exists := c.Get("machine_context")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "machine context not set",
			})
			return
		}

		ctx := machineCtx.(*MachineContext)
		c.JSON(http.StatusOK, gin.H{
			"status":   "ok",
			"app_id":   ctx.ApplicationID,
			"roles":    ctx.Roles,
			"identity": ctx.Identity,
		})
	})

	tests := []struct {
		name           string
		tokenClaims    UnifiedClaims
		expectedStatus int
		expectedError  string
	}{
		{
			name: "machine token succeeds",
			tokenClaims: UnifiedClaims{
				// TODO: Uncomment and verify token structure
				AuthorizedParty: "8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // Valid Azure AD App ID (UUID)
				Roles:           []string{"api.write", "api.read"},
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "app:8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7", // TODO: Verify subject format
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "machine token with different roles also succeeds",
			tokenClaims: UnifiedClaims{
				// TODO: Uncomment and verify token structure
				AuthorizedParty: "ce306f4f-63ea-4ae3-98ce-1dba7572e990", // Valid Azure AD App ID (UUID)
				Roles:           []string{"api.read"},
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "app:ce306f4f-63ea-4ae3-98ce-1dba7572e990", // Valid Azure AD App subject format
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "user token is rejected",
			tokenClaims: UnifiedClaims{
				// TODO: Uncomment and verify token structure
				UniqueID: "123456",    // TODO: Verify user ID format
				Name:     "Test User", // TODO: Verify name format
				Roles:    []string{"api.write"},
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "user:123456", // TODO: Verify subject format
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "machine token required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create token using clean API
			tokenString, err := SignUnified(tt.tokenClaims, secret)
			require.NoError(t, err)

			// Make request
			req := httptest.NewRequest("GET", "/m2m-endpoint", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)
			w := httptest.NewRecorder()

			// Process request
			router.ServeHTTP(w, req)

			// Verify response
			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errorResponse map[string]string
				err := json.NewDecoder(w.Body).Decode(&errorResponse)
				require.NoError(t, err)
				assert.Contains(t, errorResponse["error"], tt.expectedError)
			}
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
			(validErr == "token is malformed" && err.Error() == "JWKS validation failed: token is malformed: could not base64 decode signature: illegal base64 data at input byte 16") ||
			(validErr == "invalid signature" && (err.Error() == "JWKS validation: invalid token signature: token is malformed: could not base64 decode signature: illegal base64 data at input byte 16" ||
				err.Error() == "JWKS validation: invalid token signature: "+validErr))) {
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
		assert.Equal(t, "4cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a3", GetPrincipalID(claims))
		// Note: EPFL-specific type checks moved to epfl package
	})

	// Test with GenericValidator
	t.Run("GenericValidator", func(t *testing.T) {
		config := Config{
			Method: SigningPublicKey,
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
		assert.Contains(t, err.Error(), "header parsing")
		assert.Contains(t, err.Error(), "invalid token format")
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

		tokenString, err := SignUnified(claims, []byte("secret"))
		require.NoError(t, err)

		_, err = validator.ValidateToken(tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
		assert.Contains(t, err.Error(), "HS256")
	})
}

// Helper function removed - using NewMachineTokenForTesting from unified_token.go instead

func TestGenericValidator_ValidationErrors(t *testing.T) {
	logger := zap.NewNop()
	secret := []byte("very-secret-key")
	config := Config{
		Method: SigningHMAC,
		Secret: secret,
	}

	validator, err := NewGenericValidator(config, logger)
	require.NoError(t, err)

	// --- Test Cases ---
	tests := []struct {
		name        string
		tokenFunc   func() string // Function to generate token
		expectedErr string
	}{
		{
			name: "malformed token (wrong number of segments)",
			tokenFunc: func() string {
				return "this.is.not.a.valid.jwt"
			},
			expectedErr: "invalid token format",
		},
		{
			name: "malformed token (bad base64 header)",
			tokenFunc: func() string {
				return "bad!base64.payload.signature"
			},
			expectedErr: "header decoding",
		},
		{
			name: "malformed token (header is not json)",
			tokenFunc: func() string {
				// "not json" base64 encoded for RawURLEncoding
				return "bm90IGpzb24.payload.signature"
			},
			expectedErr: "header JSON parsing",
		},
		{
			name: "expired token",
			tokenFunc: func() string {
				claims := UnifiedClaims{
					UniqueID: "123456",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					},
				}
				tokenString, _ := SignUnified(claims, secret)
				return tokenString
			},
			expectedErr: "token has expired",
		},
		{
			name: "token used before nbf",
			tokenFunc: func() string {
				claims := UnifiedClaims{
					UniqueID: "123456",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now().Add(time.Minute)), // Not yet valid
						IssuedAt:  jwt.NewNumericDate(time.Now()),
					},
				}
				tokenString, _ := SignUnified(claims, secret)
				return tokenString
			},
			expectedErr: "token is not valid yet",
		},
		{
			name: "invalid signature",
			tokenFunc: func() string {
				claims := UnifiedClaims{
					UniqueID: "123456",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					},
				}
				tokenString, _ := SignUnified(claims, []byte("different-secret")) // Signed with wrong key
				return tokenString
			},
			expectedErr: "signature is invalid",
		},
		// Removed: EPFL-specific UniqueID format validation moved to epfl package
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := tt.tokenFunc()
			_, err := validator.ValidateToken(tokenString)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestGenericValidator_AlgorithmSecurity(t *testing.T) {
	logger := zap.NewNop()
	secret := []byte("test-secret-key")

	tests := []struct {
		name              string
		allowedAlgorithms []string
		tokenAlgorithm    string
		expectSuccess     bool
		expectedError     string
	}{
		{
			name:              "backward compatibility - no algorithm restrictions",
			allowedAlgorithms: nil, // No restrictions
			tokenAlgorithm:    "HS256",
			expectSuccess:     true,
		},
		{
			name:              "backward compatibility - empty algorithm list",
			allowedAlgorithms: []string{}, // Empty list means no restrictions
			tokenAlgorithm:    "HS256",
			expectSuccess:     true,
		},
		{
			name:              "allowed algorithm HS256",
			allowedAlgorithms: []string{"HS256"},
			tokenAlgorithm:    "HS256",
			expectSuccess:     true,
		},
		{
			name:              "allowed algorithm RS256",
			allowedAlgorithms: []string{"RS256"},
			tokenAlgorithm:    "RS256",
			expectSuccess:     false, // Will fail because no JWKS config for RS256
			expectedError:     "public key validation requested but not configured",
		},
		{
			name:              "multiple allowed algorithms - HS256 used",
			allowedAlgorithms: []string{"HS256", "RS256"},
			tokenAlgorithm:    "HS256",
			expectSuccess:     true,
		},
		{
			name:              "disallowed algorithm HS512",
			allowedAlgorithms: []string{"HS256"},
			tokenAlgorithm:    "HS512",
			expectSuccess:     false,
			expectedError:     "unsupported algorithm",
		},
		{
			name:              "potential substitution attack - RS256 not allowed",
			allowedAlgorithms: []string{"HS256"}, // Only HMAC allowed
			tokenAlgorithm:    "RS256",           // Attacker tries RSA
			expectSuccess:     false,
			expectedError:     "unsupported algorithm",
		},
		{
			name:              "potential substitution attack - HS256 not allowed",
			allowedAlgorithms: []string{"RS256"}, // Only RSA allowed
			tokenAlgorithm:    "HS256",           // Attacker tries HMAC with public key
			expectSuccess:     false,
			expectedError:     "unsupported algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with algorithm restrictions
			config := Config{
				Method:            SigningHMAC,
				Secret:            secret,
				AllowedAlgorithms: tt.allowedAlgorithms,
			}

			validator, err := NewGenericValidator(config, logger)
			require.NoError(t, err)

			// Create a token with the specified algorithm
			var tokenString string
			if tt.tokenAlgorithm == "HS256" || tt.tokenAlgorithm == "HS512" {
				// Create HMAC token
				claims := UnifiedClaims{
					UniqueID: "123456",
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   "test-user",
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					},
				}

				// Use appropriate signing method
				var signingMethod jwt.SigningMethod
				if tt.tokenAlgorithm == "HS512" {
					signingMethod = jwt.SigningMethodHS512
				} else {
					signingMethod = jwt.SigningMethodHS256
				}

				token := jwt.NewWithClaims(signingMethod, claims)
				tokenString, err = token.SignedString(secret)
				require.NoError(t, err)
			} else {
				// Create a token with RSA algorithm (will fail validation but tests algorithm check)
				// We create this manually to test the algorithm validation before it reaches JWKS
				header := map[string]interface{}{
					"alg": tt.tokenAlgorithm,
					"typ": "JWT",
				}
				claims := map[string]interface{}{
					"uniqueid": "123456",
					"sub":      "test-user",
					"exp":      time.Now().Add(time.Hour).Unix(),
				}

				headerJSON, _ := json.Marshal(header)
				claimsJSON, _ := json.Marshal(claims)

				headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
				claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

				// Create a token with fake signature (algorithm validation happens before signature validation)
				tokenString = headerB64 + "." + claimsB64 + ".fake-signature"
			}

			// Validate the token
			_, err = validator.ValidateToken(tokenString)

			if tt.expectSuccess {
				assert.NoError(t, err, "Token validation should succeed")
			} else {
				require.Error(t, err, "Token validation should fail")
				assert.Contains(t, err.Error(), tt.expectedError, "Error should contain expected message")
			}
		})
	}
}

func TestGenericValidator_AlgorithmSubstitutionAttack(t *testing.T) {
	logger := zap.NewNop()

	t.Run("prevent HS256 substitution when only RS256 allowed", func(t *testing.T) {
		// Scenario: System configured for RSA tokens only, attacker tries HMAC with public key
		config := Config{
			Method: SigningPublicKey,
			JWKSConfig: &JWKSConfig{
				BaseURL:     "https://login.microsoftonline.com",
				KeyCacheTTL: time.Hour,
			},
			AllowedAlgorithms: []string{"RS256"}, // Only RSA allowed
		}

		validator, err := NewGenericValidator(config, logger)
		require.NoError(t, err)

		// Attacker creates HMAC token using HS256 (classic substitution attack)
		claims := UnifiedClaims{
			UniqueID: "123456",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "attacker",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		// This would be signed with public key as HMAC secret in real attack
		fakeSecret := []byte("fake-public-key-content")
		tokenString, err := SignUnified(claims, fakeSecret)
		require.NoError(t, err)

		// Validation should fail due to algorithm restriction
		_, err = validator.ValidateToken(tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
		assert.Contains(t, err.Error(), "security violation")
	})

	t.Run("prevent RS256 substitution when only HS256 allowed", func(t *testing.T) {
		// Scenario: System configured for HMAC tokens only, attacker tries RSA
		secret := []byte("hmac-secret")
		config := Config{
			Method:            SigningHMAC,
			Secret:            secret,
			AllowedAlgorithms: []string{"HS256"}, // Only HMAC allowed
		}

		validator, err := NewGenericValidator(config, logger)
		require.NoError(t, err)

		// Create fake RSA token (algorithm validation happens before signature validation)
		header := map[string]interface{}{
			"alg": "RS256", // Attacker claims RSA
			"typ": "JWT",
		}
		claimsMap := map[string]interface{}{
			"uniqueid": "123456",
			"sub":      "attacker",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		headerJSON, _ := json.Marshal(header)
		claimsJSON, _ := json.Marshal(claimsMap)

		headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
		claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

		tokenString := headerB64 + "." + claimsB64 + ".fake-rsa-signature"

		// Validation should fail due to algorithm restriction
		_, err = validator.ValidateToken(tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
		assert.Contains(t, err.Error(), "security violation")
	})
}
