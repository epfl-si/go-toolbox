package token

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func ExampleUnifiedClaims_basic() {
	// Create unified claims for a person
	claims := UnifiedClaims{
		UniqueID: "123456", // SCIPER
		Name:     "John Doe",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "john.doe@epfl.ch",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create and sign token using clean API
	tokenString, err := SignUnified(claims, []byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse token back using clean API
	parsedClaims, err := ParseUnifiedHMAC(tokenString, []byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("UniqueID: %s\n", parsedClaims.UniqueID)
	fmt.Printf("Name: %s\n", parsedClaims.Name)
	fmt.Printf("Subject: %s\n", parsedClaims.Subject)

	// Output:
	// UniqueID: 123456
	// Name: John Doe
	// Subject: john.doe@epfl.ch
}

func ExampleHMACValidator() {
	logger := zap.NewNop()
	secret := []byte("my-secret")

	// Create HMAC validator
	validator := NewHMACValidator(secret, logger, Config{})

	// Create a test token
	claims := UnifiedClaims{
		UniqueID: "654321",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	tokenString, err := SignUnified(claims, secret)
	if err != nil {
		fmt.Printf("Error signing token: %v\n", err)
		return
	}

	// Validate the token
	validatedClaims, err := validator.ValidateToken(tokenString)
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Validated UniqueID: %s\n", validatedClaims.UniqueID)
	fmt.Printf("Principal ID: %s\n", GetPrincipalID(validatedClaims))
	// Note: IsPerson check moved to epfl package

	// Output:
	// Validated UniqueID: 654321
	// Principal ID: 654321
}

func ExampleUnifiedClaims_entraID() {
	// Example of Entra ID token claims structure
	claims := &UnifiedClaims{
		UniqueID: "M02575",
		Email:    "service@epfl.ch",
		Groups:   []string{"admin", "users"},
		TenantID: "tenant-id",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "service-account",
			Issuer:    "https://login.microsoftonline.com/tenant-id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	fmt.Printf("Service Account ID: %s\n", claims.UniqueID)
	fmt.Printf("Email: %s\n", claims.Email)
	fmt.Printf("Groups: %v\n", claims.Groups)
	// Note: IsService check moved to epfl package

	// Output:
	// Service Account ID: M02575
	// Email: service@epfl.ch
	// Groups: [admin users]
}

func ExampleUnifiedClaims_unknownType() {
	// Token with no UniqueID (unknown type, uses standard JWT claims)
	claims := UnifiedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "my-service@epfl.ch",
			Audience: []string{"target-api"},
		},
	}

	// Create and sign token using clean API
	tokenString, err := SignUnified(claims, []byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse token back using clean API
	parsedClaims, err := ParseUnifiedHMAC(tokenString, []byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Principal ID: %s\n", GetPrincipalID(parsedClaims))
	// Note: IsPerson/IsService checks moved to epfl package

	// Output:
	// Principal ID: my-service@epfl.ch
}

func ExampleUnifiedClaims_serviceAccount() {
	// Service account token with M+5digits UniqueID
	claims := UnifiedClaims{
		UniqueID: "M02575", // Service account pattern: M + 5 digits
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "service-api@epfl.ch",
			Audience: []string{"target-api"},
		},
	}

	// Create and sign token using clean API
	tokenString, err := SignUnified(claims, []byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse token back using clean API
	parsedClaims, err := ParseUnifiedHMAC(tokenString, []byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Principal ID: %s\n", GetPrincipalID(parsedClaims))
	// Note: IsPerson/IsService checks moved to epfl package

	// Output:
	// Principal ID: M02575
}

func ExampleUnifiedClaims_machineToken() {
	// Example: Microsoft Entra application token with roles

	claims := UnifiedClaims{
		AuthorizedParty: "ce306f4f-63ea-4ae3-98ce-1dba7572e990",
		ObjectID:        "4cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a3",
		Roles:           []string{"api.read", "api.write"},
		TenantID:        "b6cddbc1-2348-4644-af0a-2fdb55573e3b",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "application-service",
			Issuer:    "https://sts.windows.net/b6cddbc1-2348-4644-af0a-2fdb55573e3b/",
			Audience:  []string{"api://ce306f4f-63ea-4ae3-98ce-1dba7572e990"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// Use claims variable to avoid compiler error
	_ = claims

	// Check token type
	fmt.Printf("Token Type: %s\n", GetTokenType(&claims))
	fmt.Printf("Is Machine: %t\n", IsMachineToken(&claims))

	// Extract machine-specific information
	fmt.Printf("Application ID: %s\n", GetApplicationID(&claims))
	fmt.Printf("Service Principal ID: %s\n", GetServicePrincipalID(&claims))
	fmt.Printf("Has api.read role: %t\n", HasApplicationRole(&claims, "api.read"))
	fmt.Printf("Identity: %s\n", GetIdentity(&claims))

	// Extract complete machine context
	machineCtx := ExtractMachineContext(&claims)
	fmt.Printf("Machine Context - App: %s, Roles: %v\n",
		machineCtx.ApplicationID, machineCtx.Roles)

	fmt.Println("Machine token example")

	// Output:
	// Token Type: machine
	// Is Machine: true
	// Application ID: ce306f4f-63ea-4ae3-98ce-1dba7572e990
	// Service Principal ID: 4cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a3
	// Has api.read role: true
	// Identity: Application:ce306f4f-63ea-4ae3-98ce-1dba7572e990
	// Machine Context - App: ce306f4f-63ea-4ae3-98ce-1dba7572e990, Roles: [api.read api.write]
	// Machine token example
}

func ExampleMachineTokenMiddleware() {
	logger := zap.NewNop()
	secret := []byte("my-secret")

	// Create HMAC validator for local tokens
	validator := NewHMACValidator(secret, logger, Config{})

	// Create Gin router with machine token middleware
	router := gin.New()

	// M2M endpoint requiring machine tokens
	router.Use(MachineTokenMiddleware(validator, logger))
	router.POST("/admin/action", func(c *gin.Context) {
		// Extract machine context
		machineCtx, _ := c.Get("machine_context")
		ctx := machineCtx.(*MachineContext)

		c.JSON(http.StatusOK, gin.H{
			"message": "Admin action executed",
			"app_id":  ctx.ApplicationID,
		})
	})

	fmt.Println("Machine-only endpoint configured")
	// Output: Machine-only endpoint configured
}

func ExampleNewMachineTokenForTesting() {
	// Create a machine token for testing
	secret := []byte("test-secret")
	tokenString, err := NewMachineTokenForTesting(
		"test-8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7",
		[]string{"api.read", "api.write"},
		secret,
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse the token to verify
	claims, err := ParseUnifiedHMAC(tokenString, secret)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Created machine token for app: %s\n", claims.AuthorizedParty)
	fmt.Printf("Token type: %s\n", GetTokenType(claims))
	fmt.Printf("Roles: %v\n", claims.Roles)

	// Output:
	// Created machine token for app: test-8cf9b4d1-4b30-48e4-98d8-8c3b02c1e2a7
	// Token type: machine
	// Roles: [api.read api.write]
}
