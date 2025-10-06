package token

import (
	"errors"
	"fmt"
)

// Structured error constants for programmatic error handling
var (
	// Validation errors
	ErrTokenExpired      = errors.New("token has expired")
	ErrTokenNotYetValid  = errors.New("token is not valid yet")
	ErrTokenIssuedFuture = errors.New("token was issued in the future")
	ErrInvalidSignature  = errors.New("invalid token signature")
	ErrInvalidIssuer     = errors.New("invalid issuer")
	ErrInvalidAudience   = errors.New("invalid audience")
	ErrInvalidAlgorithm  = errors.New("unsupported algorithm")
	ErrAlgNone           = errors.New("algorithm 'none' is not allowed")
	ErrTokenInvalid      = errors.New("token is invalid")

	// Configuration errors
	ErrNoValidationMethod     = errors.New("no validation method configured")
	ErrInvalidConfig          = errors.New("invalid configuration")
	ErrValidatorNotConfigured = errors.New("validator not configured for this method")

	// JWKS errors
	ErrJWKSFetchFailed = errors.New("failed to fetch JWKS")
	ErrJWKSParseFailed = errors.New("failed to parse JWKS")
	ErrKeyNotFound     = errors.New("signing key not found")
	ErrJWKSTimeout     = errors.New("JWKS request timeout")

	// Claims errors
	ErrInvalidClaims     = errors.New("invalid claims")
	ErrMissingIdentifier = errors.New("missing required identifier")
	ErrInvalidUniqueID   = errors.New("invalid uniqueid format")
	ErrInvalidEmail      = errors.New("invalid email format")

	// Token parsing errors
	ErrInvalidTokenFormat = errors.New("invalid token format")
	ErrHeaderParseFailed  = errors.New("failed to parse token header")
	ErrUnexpectedMethod   = errors.New("unexpected signing method")
)

// ValidationError wraps an error with additional context for better error handling
type ValidationError struct {
	Err     error  // The underlying error
	Context string // Context where the error occurred
	Field   string // Which field failed validation (optional)
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (field: %s)", e.Context, e.Err, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Context, e.Err)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// NewValidationError creates a new ValidationError with context
func NewValidationError(err error, context string, field ...string) *ValidationError {
	ve := &ValidationError{
		Err:     err,
		Context: context,
	}
	if len(field) > 0 {
		ve.Field = field[0]
	}
	return ve
}
