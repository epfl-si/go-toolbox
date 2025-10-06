package epfl

import (
	"regexp"

	"github.com/epfl-si/go-toolbox/token/v2"
)

// User type constants for EPFL users
const (
	UserTypePerson  = "person"
	UserTypeService = "service"
	UserTypeUnknown = "unknown"
)

var (
	sciperPattern  = regexp.MustCompile(`^\d{6}$`)
	servicePattern = regexp.MustCompile(`^M\d{5}$`)
)

// IsPerson checks if claims represent a person (SCIPER)
func IsPerson(claims *token.UnifiedClaims) bool {
	return claims.UniqueID != "" && sciperPattern.MatchString(claims.UniqueID)
}

// IsService checks if claims represent a service account
func IsService(claims *token.UnifiedClaims) bool {
	return claims.UniqueID != "" && servicePattern.MatchString(claims.UniqueID)
}

// GetUserType returns the type of user based on UniqueID
func GetUserType(claims *token.UnifiedClaims) string {
	if IsPerson(claims) {
		return UserTypePerson
	}
	if IsService(claims) {
		return UserTypeService
	}
	return UserTypeUnknown
}
