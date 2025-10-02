package token_test

import (
	"fmt"
	"time"

	"github.com/epfl-si/go-toolbox/token"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func ExampleUnifiedClaims_basic() {
	// Create unified claims for a person
	claims := token.UnifiedClaims{
		UniqueID: "123456", // SCIPER
		Name:     "John Doe",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "john.doe@epfl.ch",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create and sign token
	t := token.NewUnified(claims)
	tokenString, err := t.Sign([]byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse token back
	parsedClaims, err := token.ParseUnified(tokenString, []byte("secret"))
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
	validator := token.NewHMACValidator(secret, logger)

	// Create a test token
	claims := token.UnifiedClaims{
		UniqueID: "654321",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	t := token.NewUnified(claims)
	tokenString, err := t.Sign(secret)
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
	fmt.Printf("User ID: %s\n", token.GetUserID(validatedClaims))
	fmt.Printf("Is Person: %t\n", token.IsPerson(validatedClaims))

	// Output:
	// Validated UniqueID: 654321
	// User ID: 654321
	// Is Person: true
}

func ExampleUnifiedClaims_entraID() {
	// Example of Entra ID token claims structure
	claims := &token.UnifiedClaims{
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
	fmt.Printf("Is Service: %t\n", token.IsService(claims))

	// Output:
	// Service Account ID: M02575
	// Email: service@epfl.ch
	// Groups: [admin users]
	// Is Service: true
}

func ExampleCustomClaims_migration() {
	// Existing CustomClaims usage
	oldClaims := token.CustomClaims{
		Sciper: "789012",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "old-user",
		},
	}

	// Convert to unified claims
	unified := oldClaims.ToUnifiedClaims()
	fmt.Printf("Unified UniqueID: %s\n", unified.UniqueID) // Mapped from sciper

	// Convert back for compatibility
	backToOld := unified.ToCustomClaims()
	fmt.Printf("Back to old SCIPER: %s\n", backToOld.Sciper)

	// Output:
	// Unified UniqueID: 789012
	// Back to old SCIPER: 789012
}

func ExampleUnifiedClaims_unknownType() {
	// Token with no UniqueID (unknown type, uses standard JWT claims)
	claims := token.UnifiedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "my-service@epfl.ch",
			Audience: []string{"target-api"},
		},
	}

	// Create and sign token
	t := token.NewUnified(claims)
	tokenString, err := t.Sign([]byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse token back
	parsedClaims, err := token.ParseUnified(tokenString, []byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("User ID: %s\n", token.GetUserID(parsedClaims))
	fmt.Printf("Is Service: %t\n", token.IsService(parsedClaims))
	fmt.Printf("Is Person: %t\n", token.IsPerson(parsedClaims))

	// Output:
	// User ID: my-service@epfl.ch
	// Is Service: false
	// Is Person: false
}

func ExampleUnifiedClaims_serviceAccount() {
	// Service account token with M+5digits UniqueID
	claims := token.UnifiedClaims{
		UniqueID: "M02575", // Service account pattern: M + 5 digits
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "service-api@epfl.ch",
			Audience: []string{"target-api"},
		},
	}

	// Create and sign token
	t := token.NewUnified(claims)
	tokenString, err := t.Sign([]byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse token back
	parsedClaims, err := token.ParseUnified(tokenString, []byte("secret"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("User ID: %s\n", token.GetUserID(parsedClaims))
	fmt.Printf("Is Service: %t\n", token.IsService(parsedClaims))
	fmt.Printf("Is Person: %t\n", token.IsPerson(parsedClaims))

	// Output:
	// User ID: M02575
	// Is Service: true
	// Is Person: false
}
