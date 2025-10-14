package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	keyfunc "github.com/MicahParks/keyfunc/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// SigningMethod defines the cryptographic signing strategy
type SigningMethod string

const (
	// SigningHMAC is the HMAC signing method (symmetric key)
	SigningHMAC SigningMethod = "hmac"
	// SigningPublicKey is the public key signing method (asymmetric, RSA/ECDSA via JWKS)
	SigningPublicKey SigningMethod = "publickey"
)

// Config defines the validation strategy and settings
type Config struct {
	// Validation method
	Method SigningMethod `json:"method"`

	// For HMAC validation
	Secret []byte `json:"secret,omitempty"`

	// For JWKS validation
	JWKSConfig *JWKSConfig `json:"jwks_config,omitempty"`

	// Optional validation constraints
	RequiredIssuer   string   `json:"required_issuer,omitempty"`
	RequiredAudience []string `json:"required_audience,omitempty"`

	// Security: Algorithm whitelist to prevent substitution attacks
	// If empty, all algorithms are allowed (backward compatibility)
	// Recommended: ["HS256"] for HMAC-only, ["RS256"] for JWKS-only, or both for mixed
	AllowedAlgorithms []string `json:"allowed_algorithms,omitempty"`
}

// JWKSConfig contains settings for JWKS validation
type JWKSConfig struct {
	// For Entra ID: https://login.microsoftonline.com
	BaseURL     string        `json:"base_url"`
	TenantID    string        `json:"tenant_id,omitempty"` // Optional for static tenant
	KeyCacheTTL time.Duration `json:"key_cache_ttl"`       // Default: 5min if zero
}

// JWKSCache represents a thread-safe in-memory cache for JWKS keys
type JWKSCache struct {
	keys  map[string]*CachedKey
	mutex sync.RWMutex
}

// CachedKey represents a cached JWKS key with expiration
type CachedKey struct {
	KeyFuncProvider keyfunc.Keyfunc
	ExpiresAt       time.Time
}

// Validate validates application-specific claim requirements.
// Note: JWT time claims (exp, nbf, iat) are validated automatically by the JWT library.
func (u UnifiedClaims) Validate() error {
	// Validate at least one identifier exists
	if u.UniqueID == "" && u.Subject == "" && len(u.Audience) == 0 {
		return NewValidationError(ErrMissingIdentifier, "claims validation", "uniqueid/sub/aud")
	}

	// Validate email format if present
	if u.Email != "" {
		if !isValidEmail(u.Email) {
			return NewValidationError(
				fmt.Errorf("%w: %s", ErrInvalidEmail, u.Email),
				"claims validation",
				"email",
			)
		}
	}

	return nil
}

// isValidEmail checks if the email format is valid
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// parseJWTHeader parses the JWT header part without validation
func parseJWTHeader(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, NewValidationError(ErrInvalidTokenFormat, "header parsing")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, NewValidationError(
			fmt.Errorf("%w: %v", ErrHeaderParseFailed, err),
			"header decoding",
		)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, NewValidationError(
			fmt.Errorf("%w: %v", ErrHeaderParseFailed, err),
			"header JSON parsing",
		)
	}

	// Explicit protection against alg=none vulnerability
	if alg, ok := header["alg"].(string); ok {
		if strings.ToLower(alg) == "none" {
			return nil, NewValidationError(ErrAlgNone, "algorithm validation", "alg")
		}
	}

	return header, nil
}

// validateStandardClaims performs optional validation of issuer and audience
func validateStandardClaims(claims *UnifiedClaims, config Config) error {
	// Validate issuer if configured
	if config.RequiredIssuer != "" {
		if claims.Issuer != config.RequiredIssuer {
			return NewValidationError(
				fmt.Errorf("%w: expected %s, got %s", ErrInvalidIssuer, config.RequiredIssuer, claims.Issuer),
				"standard claims validation",
				"iss",
			)
		}
	}

	// Validate audience if configured
	if len(config.RequiredAudience) > 0 {
		found := false
		for _, required := range config.RequiredAudience {
			for _, aud := range claims.Audience {
				if aud == required {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return NewValidationError(
				fmt.Errorf("%w: expected one of %v, got %v", ErrInvalidAudience, config.RequiredAudience, claims.Audience),
				"standard claims validation",
				"aud",
			)
		}
	}

	return nil
}

// validateAlgorithm checks if the token's algorithm is in the allowed list
// Returns nil if allowed or if no restrictions are configured (backward compatibility)
func validateAlgorithm(algorithm string, allowedAlgorithms []string) error {
	// If no algorithm restrictions are configured, allow all algorithms (backward compatibility)
	if len(allowedAlgorithms) == 0 {
		return nil
	}

	// Check if the algorithm is in the allowed list
	for _, allowed := range allowedAlgorithms {
		if algorithm == allowed {
			return nil
		}
	}

	return NewValidationError(
		fmt.Errorf("%w: '%s' not in allowed list %v", ErrInvalidAlgorithm, algorithm, allowedAlgorithms),
		"algorithm validation",
		"alg",
	)
}

// TokenValidator defines the interface for token validation
type TokenValidator interface {
	ValidateToken(tokenString string) (*UnifiedClaims, error)
}

// JWKSValidator handles JWKS-based token validation
type JWKSValidator struct {
	baseURL     string
	tenantID    string
	keyCache    *JWKSCache
	cacheTTL    time.Duration
	logger      *zap.Logger
	httpClient  *http.Client
	stopCleanup chan struct{}
	cleanupWg   sync.WaitGroup
	config      Config
}

// NewJWKSValidator creates a new JWKS validator
func NewJWKSValidator(baseURL, tenantID string, cacheTTL time.Duration, logger *zap.Logger) *JWKSValidator {
	return NewJWKSValidatorWithClient(baseURL, tenantID, cacheTTL, logger, nil, Config{})
}

// NewJWKSValidatorWithClient creates a new JWKS validator with custom HTTP client
func NewJWKSValidatorWithClient(baseURL, tenantID string, cacheTTL time.Duration, logger *zap.Logger, client *http.Client, config Config) *JWKSValidator {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second, // Default safe timeout
		}
	}

	validator := &JWKSValidator{
		baseURL:     baseURL,
		tenantID:    tenantID,
		keyCache:    &JWKSCache{keys: make(map[string]*CachedKey)},
		cacheTTL:    cacheTTL,
		logger:      logger,
		httpClient:  client,
		stopCleanup: make(chan struct{}),
		config:      config,
	}

	// Start background cleanup goroutine
	validator.cleanupWg.Add(1)
	go validator.cleanupExpiredKeys()

	return validator
}

// ValidateToken validates a token using JWKS
func (v *JWKSValidator) ValidateToken(tokenString string) (*UnifiedClaims, error) {
	claims := &UnifiedClaims{}

	// Parse header without validation to determine signing method
	header, err := parseJWTHeader(tokenString)
	if err != nil {
		return nil, err // Already wrapped with structured error
	}

	// Verify signing method is RSA or ECDSA
	alg, _ := header["alg"].(string)
	if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "ES") {
		return nil, NewValidationError(
			fmt.Errorf("%w: %v, expected RSA or ECDSA", ErrUnexpectedMethod, alg),
			"JWKS validation",
			"alg",
		)
	}

	// Parse claims without validation for JWKS URL construction
	tempClaims := jwt.MapClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(tokenString, &tempClaims); err != nil {
		return nil, NewValidationError(
			fmt.Errorf("failed to extract claims for JWKS URL: %w", err),
			"JWKS validation",
		)
	}

	// Get tenant ID from token or fallback to configured tenant
	tenantID := v.tenantID
	if tid, ok := tempClaims["tid"].(string); ok {
		tenantID = tid
	}

	// Construct JWKS URL
	jwksURL := fmt.Sprintf("%s/%s/discovery/v2.0/keys", v.baseURL, tenantID)
	// Note: Microsoft JWKS endpoint doesn't accept appid parameter, it returns all keys for the tenant

	// Get key function with caching
	keyFunc, err := v.getKeyFunc(jwksURL)
	if err != nil {
		return nil, err // Already wrapped with structured error
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return nil, NewValidationError(
			fmt.Errorf("%w: %v", ErrInvalidSignature, err),
			"JWKS validation",
		)
	}

	if !token.Valid {
		return nil, NewValidationError(ErrTokenInvalid, "JWKS validation")
	}

	// Validate claims
	if err := claims.Validate(); err != nil {
		return nil, err // Already wrapped with structured error
	}

	// Optional validation of standard claims
	if err := validateStandardClaims(claims, v.config); err != nil {
		return nil, err // Already wrapped with structured error
	}

	return claims, nil
}

// getKeyFunc creates a cached key function for JWKS validation
func (v *JWKSValidator) getKeyFunc(jwksURL string) (jwt.Keyfunc, error) {
	// Check cache first with read lock
	v.keyCache.mutex.RLock()
	if cachedKey, exists := v.keyCache.keys[jwksURL]; exists {
		if time.Now().Before(cachedKey.ExpiresAt) {
			keyFunc := cachedKey.KeyFuncProvider.Keyfunc
			v.keyCache.mutex.RUnlock()
			return keyFunc, nil
		}
	}
	v.keyCache.mutex.RUnlock()

	// Key not found or expired, acquire write lock to update cache
	v.keyCache.mutex.Lock()
	defer v.keyCache.mutex.Unlock()

	// Double-check in case another goroutine updated the cache
	if cachedKey, exists := v.keyCache.keys[jwksURL]; exists {
		if time.Now().Before(cachedKey.ExpiresAt) {
			return cachedKey.KeyFuncProvider.Keyfunc, nil
		}
		// Key expired, remove it
		delete(v.keyCache.keys, jwksURL)
	}

	// Fetch new JWKS
	jwksString, err := v.getJwks(jwksURL)
	if err != nil {
		return nil, NewValidationError(
			fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err),
			"JWKS key function",
		)
	}

	// Parse JWKS
	jwks, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwksString))
	if err != nil {
		return nil, NewValidationError(
			fmt.Errorf("%w: %v", ErrJWKSParseFailed, err),
			"JWKS key function",
		)
	}

	// Cache the key function provider
	v.keyCache.keys[jwksURL] = &CachedKey{
		KeyFuncProvider: jwks,
		ExpiresAt:       time.Now().Add(v.cacheTTL),
	}

	// Return the actual key function
	return jwks.Keyfunc, nil
}

// Close stops the background cleanup goroutine
func (v *JWKSValidator) Close() error {
	select {
	case <-v.stopCleanup:
		// Already closed
		return nil
	default:
		close(v.stopCleanup)
		v.cleanupWg.Wait() // Wait for cleanup goroutine to finish
	}
	return nil
}

// cleanupExpiredKeys periodically removes expired keys from the cache
func (v *JWKSValidator) cleanupExpiredKeys() {
	defer v.cleanupWg.Done()
	ticker := time.NewTicker(v.cacheTTL / 2) // Clean up every half cache TTL
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			v.keyCache.mutex.Lock()

			for url, cachedKey := range v.keyCache.keys {
				if now.After(cachedKey.ExpiresAt) {
					delete(v.keyCache.keys, url)
					v.logger.Debug("Removed expired JWKS key from cache",
						zap.String("jwks_url", url),
						zap.Time("expired_at", cachedKey.ExpiresAt))
				}
			}

			v.keyCache.mutex.Unlock()
		case <-v.stopCleanup:
			v.logger.Debug("Stopping JWKS cleanup goroutine")
			return
		}
	}
}

// HMACValidator handles HMAC-based token validation
type HMACValidator struct {
	secret []byte
	logger *zap.Logger
	config Config
}

// NewHMACValidator creates a new HMAC validator
func NewHMACValidator(secret []byte, logger *zap.Logger, config Config) *HMACValidator {
	return &HMACValidator{
		secret: secret,
		logger: logger,
		config: config,
	}
}

// ValidateToken validates a token using HMAC
func (v *HMACValidator) ValidateToken(tokenString string) (*UnifiedClaims, error) {
	claims := &UnifiedClaims{}

	// Parse header without validation to determine signing method
	header, err := parseJWTHeader(tokenString)
	if err != nil {
		return nil, err // Already wrapped with structured error
	}

	// Verify signing method is HMAC
	alg, _ := header["alg"].(string)
	if !strings.HasPrefix(alg, "HS") {
		return nil, NewValidationError(
			fmt.Errorf("%w: %v, expected HMAC", ErrUnexpectedMethod, alg),
			"HMAC validation",
			"alg",
		)
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return v.secret, nil
	})

	if err != nil {
		return nil, NewValidationError(
			fmt.Errorf("%w: %v", ErrInvalidSignature, err),
			"HMAC validation",
		)
	}

	if !token.Valid {
		return nil, NewValidationError(ErrTokenInvalid, "HMAC validation")
	}

	// Validate claims
	if err := claims.Validate(); err != nil {
		return nil, err // Already wrapped with structured error
	}

	// Optional validation of standard claims
	if err := validateStandardClaims(claims, v.config); err != nil {
		return nil, err // Already wrapped with structured error
	}

	return claims, nil
}

// ChainedValidator allows combining multiple validators
type ChainedValidator struct {
	validators []TokenValidator
	logger     *zap.Logger
}

// NewChainedValidator creates a new chained validator
func NewChainedValidator(validators []TokenValidator, logger *zap.Logger) *ChainedValidator {
	return &ChainedValidator{
		validators: validators,
		logger:     logger,
	}
}

// ValidateToken tries each validator in sequence until one succeeds
func (v *ChainedValidator) ValidateToken(tokenString string) (*UnifiedClaims, error) {
	var lastErr error
	for _, validator := range v.validators {
		claims, err := validator.ValidateToken(tokenString)
		if err == nil {
			return claims, nil
		}
		lastErr = err
		v.logger.Debug("Validator failed, trying next",
			zap.String("validator", fmt.Sprintf("%T", validator)),
			zap.Error(err))
	}
	return nil, lastErr
}

// GetPrincipalID returns the primary identifier for the token's subject.
// This works for both user tokens and machine tokens:
// - For user tokens: UniqueID (SCIPER/service account) or Subject
// - For machine tokens: Subject or first Audience
// - Returns empty string if no identifier found
func GetPrincipalID(claims *UnifiedClaims) string {
	// Priority 1: UniqueID (EPFL-specific: SCIPER or service account)
	if claims.UniqueID != "" {
		return claims.UniqueID
	}
	// Priority 2: Subject claim (JWT standard)
	if claims.Subject != "" {
		return claims.Subject
	}
	// Priority 3: First audience (fallback for some machine tokens)
	if len(claims.Audience) > 0 {
		return claims.Audience[0]
	}
	return ""
}

// getJwks fetches JWKS with timeout support
func (v *JWKSValidator) getJwks(jwksURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return "", NewValidationError(
			fmt.Errorf("failed to create JWKS request: %w", err),
			"JWKS fetch",
		)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		// Check if it's a timeout error
		if ctx.Err() == context.DeadlineExceeded {
			return "", NewValidationError(ErrJWKSTimeout, "JWKS fetch")
		}
		return "", NewValidationError(
			fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err),
			"JWKS fetch",
		)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", NewValidationError(
			fmt.Errorf("%w: endpoint returned status %d", ErrJWKSFetchFailed, resp.StatusCode),
			"JWKS fetch",
		)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", NewValidationError(
			fmt.Errorf("failed to read JWKS response: %w", err),
			"JWKS fetch",
		)
	}

	return string(data), nil
}

// GenericValidator provides a unified validator that can handle both HMAC and JWKS tokens
type GenericValidator struct {
	config Config
	hmac   *HMACValidator
	jwks   *JWKSValidator
	logger *zap.Logger
}

// NewGenericValidator creates a new generic validator that can handle both HMAC and JWKS tokens
func NewGenericValidator(config Config, logger *zap.Logger) (*GenericValidator, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	validator := &GenericValidator{
		config: config,
		logger: logger,
	}

	// Initialize HMAC validator if secret is provided
	if len(config.Secret) > 0 {
		validator.hmac = NewHMACValidator(config.Secret, logger, config)
	}

	// Initialize JWKS validator if JWKS config is provided
	if config.JWKSConfig != nil {
		cacheTTL := config.JWKSConfig.KeyCacheTTL
		if cacheTTL == 0 {
			cacheTTL = 5 * time.Minute // Default
		}

		validator.jwks = NewJWKSValidatorWithClient(
			config.JWKSConfig.BaseURL,
			config.JWKSConfig.TenantID,
			cacheTTL,
			logger,
			nil,
			config,
		)
	}

	// Ensure at least one validator is configured
	if validator.hmac == nil && validator.jwks == nil {
		return nil, NewValidationError(ErrNoValidationMethod, "generic validator configuration")
	}

	return validator, nil
}

// determineSigningMethod determines which signing method to use based on the token's algorithm
func (v *GenericValidator) determineSigningMethod(token *jwt.Token) SigningMethod {
	if alg, ok := token.Header["alg"].(string); ok {
		switch {
		case strings.HasPrefix(alg, "HS"):
			return SigningHMAC
		case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "ES"):
			return SigningPublicKey
		}
	}
	// Fallback to configured method
	return v.config.Method
}

// Close stops any background resources used by the validator
func (v *GenericValidator) Close() error {
	if v.jwks != nil {
		return v.jwks.Close()
	}
	return nil
}

// ValidateToken parses and validates a token string. It automatically determines
// whether to use HMAC or JWKS validation based on the token's "alg" header field.
// SECURITY: Algorithm substitution attacks are prevented by validating against AllowedAlgorithms whitelist
func (v *GenericValidator) ValidateToken(tokenString string) (*UnifiedClaims, error) {
	// Parse header without validation to determine signing method
	header, err := parseJWTHeader(tokenString)
	if err != nil {
		return nil, err // Already wrapped with structured error
	}

	// Extract algorithm from header
	algorithm, _ := header["alg"].(string)

	// SECURITY: Validate algorithm against whitelist to prevent substitution attacks
	if err := validateAlgorithm(algorithm, v.config.AllowedAlgorithms); err != nil {
		v.logger.Warn("Algorithm validation failed - potential substitution attack",
			zap.String("algorithm", algorithm),
			zap.Strings("allowed_algorithms", v.config.AllowedAlgorithms),
			zap.Error(err))
		return nil, NewValidationError(
			fmt.Errorf("security violation: %w", err),
			"generic validation",
			"alg",
		)
	}

	// Create a dummy token to determine signing method
	dummyToken := &jwt.Token{Header: header}
	method := v.determineSigningMethod(dummyToken)

	// Log the signing method selection for debugging
	v.logger.Debug("Token signing method selected",
		zap.String("method", string(method)),
		zap.String("algorithm", algorithm))

	// Validate using appropriate validator
	switch method {
	case SigningHMAC:
		if v.hmac == nil {
			return nil, NewValidationError(ErrValidatorNotConfigured, "HMAC validation requested but not configured")
		}
		return v.hmac.ValidateToken(tokenString)
	case SigningPublicKey:
		if v.jwks == nil {
			return nil, NewValidationError(ErrValidatorNotConfigured, "public key validation requested but not configured")
		}
		return v.jwks.ValidateToken(tokenString)
	default:
		return nil, NewValidationError(
			fmt.Errorf("unsupported signing method: %s", method),
			"generic validation",
		)
	}
}
