package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

// ValidationMethod defines the validation strategy
type ValidationMethod string

const (
	// ValidationHMAC is the HMAC validation method
	ValidationHMAC ValidationMethod = "hmac"
	// ValidationJWKS is the JWKS validation method
	ValidationJWKS ValidationMethod = "jwks"
)

// Config defines the validation strategy and settings
type Config struct {
	// Validation method
	Method ValidationMethod `json:"method"`

	// For HMAC validation
	Secret []byte `json:"secret,omitempty"`

	// For JWKS validation
	JWKSConfig *JWKSConfig `json:"jwks_config,omitempty"`

	// Cache settings
	CacheEnabled bool          `json:"cache_enabled"`
	CacheTTL     time.Duration `json:"cache_ttl"`
}

// JWKSConfig contains settings for JWKS validation
type JWKSConfig struct {
	// For Entra ID: https://login.microsoftonline.com
	BaseURL     string        `json:"base_url"`
	TenantID    string        `json:"tenant_id,omitempty"` // Optional for static tenant
	KeyCacheTTL time.Duration `json:"key_cache_ttl"`
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

// Validate validates the claims of a JWT token
func (c CustomClaims) Validate() error {
	if c.Sciper == "" {
		return errors.New("sciper must be set")
	}
	return nil
}

// Validate validates the unified claims structure and its contents
func (u UnifiedClaims) Validate() error {
	// Basic identifier validation - at least one must be present
	if u.UniqueID == "" && u.Subject == "" && len(u.Audience) == 0 {
		return errors.New("at least one identifier (uniqueid, sub, or aud) must be set")
	}

	// Validate UniqueID format if present
	if u.UniqueID != "" {
		// Check SCIPER format (6 digits) or service account format (M + 5 digits)
		matched, _ := regexp.MatchString(`^(\d{6}|M\d{5})$`, u.UniqueID)
		if !matched {
			return fmt.Errorf("invalid uniqueid format: %s - must be 6 digits (SCIPER) or M+5digits (service)", u.UniqueID)
		}
	}

	// Validate email format if present
	if u.Email != "" {
		matched, _ := regexp.MatchString(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, u.Email)
		if !matched {
			return fmt.Errorf("invalid email format: %s", u.Email)
		}
	}

	// Validate JWT registered claims
	if u.ExpiresAt != nil && u.ExpiresAt.Time.Before(time.Now()) {
		return fmt.Errorf("token has expired at %v", u.ExpiresAt.Time)
	}

	if u.NotBefore != nil && u.NotBefore.Time.After(time.Now()) {
		return fmt.Errorf("token cannot be used before %v", u.NotBefore.Time)
	}

	if u.IssuedAt != nil && u.IssuedAt.Time.After(time.Now()) {
		return fmt.Errorf("token was issued in the future at %v", u.IssuedAt.Time)
	}

	return nil
}

// parseJWTHeader parses the JWT header part without validation
func parseJWTHeader(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %w", err)
	}

	return header, nil
}

// TokenValidator defines the interface for token validation
type TokenValidator interface {
	ValidateToken(tokenString string) (*UnifiedClaims, error)
}

// JWKSValidator handles JWKS-based token validation
type JWKSValidator struct {
	baseURL  string
	tenantID string
	keyCache *JWKSCache
	cacheTTL time.Duration
	logger   *zap.Logger
}

// NewJWKSValidator creates a new JWKS validator
func NewJWKSValidator(baseURL, tenantID string, cacheTTL time.Duration, logger *zap.Logger) *JWKSValidator {
	validator := &JWKSValidator{
		baseURL:  baseURL,
		tenantID: tenantID,
		keyCache: &JWKSCache{
			keys: make(map[string]*CachedKey),
		},
		cacheTTL: cacheTTL,
		logger:   logger,
	}

	// Start background cleanup goroutine
	go validator.cleanupExpiredKeys()

	return validator
}

// ValidateToken validates a token using JWKS
func (v *JWKSValidator) ValidateToken(tokenString string) (*UnifiedClaims, error) {
	claims := &UnifiedClaims{}

	// Parse header without validation to determine signing method
	header, err := parseJWTHeader(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token header: %w", err)
	}

	// Verify signing method is RSA or ECDSA
	alg, _ := header["alg"].(string)
	if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "ES") {
		return nil, fmt.Errorf("unexpected signing method: %v, expected RSA or ECDSA", alg)
	}

	// Parse claims without validation for JWKS URL construction
	tempClaims := jwt.MapClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(tokenString, &tempClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims for JWKS URL: %w", err)
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
		return nil, fmt.Errorf("failed to get JWKS key: %w", err)
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("JWKS validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	// Validate claims
	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
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
	jwksString, err := getJwks(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse JWKS
	jwks, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwksString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Cache the key function provider
	v.keyCache.keys[jwksURL] = &CachedKey{
		KeyFuncProvider: jwks,
		ExpiresAt:       time.Now().Add(v.cacheTTL),
	}

	// Return the actual key function
	return jwks.Keyfunc, nil
}

// cleanupExpiredKeys periodically removes expired keys from the cache
func (v *JWKSValidator) cleanupExpiredKeys() {
	ticker := time.NewTicker(v.cacheTTL / 2) // Clean up every half cache TTL
	defer ticker.Stop()

	for range ticker.C {
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
	}
}

// HMACValidator handles HMAC-based token validation
type HMACValidator struct {
	secret []byte
	logger *zap.Logger
}

// NewHMACValidator creates a new HMAC validator
func NewHMACValidator(secret []byte, logger *zap.Logger) *HMACValidator {
	return &HMACValidator{
		secret: secret,
		logger: logger,
	}
}

// ValidateToken validates a token using HMAC
func (v *HMACValidator) ValidateToken(tokenString string) (*UnifiedClaims, error) {
	claims := &UnifiedClaims{}

	// Parse header without validation to determine signing method
	header, err := parseJWTHeader(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token header: %w", err)
	}

	// Verify signing method is HMAC
	alg, _ := header["alg"].(string)
	if !strings.HasPrefix(alg, "HS") {
		return nil, fmt.Errorf("unexpected signing method: %v, expected HMAC", alg)
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return v.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("HMAC validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	// Validate claims
	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
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

// GetUserID extracts the user ID from unified claims
func GetUserID(claims *UnifiedClaims) string {
	// For persons: use UniqueID (SCIPER)
	if claims.UniqueID != "" {
		return claims.UniqueID
	}
	// For services: use Subject or first Audience as fallback
	if claims.Subject != "" {
		return claims.Subject
	}
	if len(claims.Audience) > 0 {
		return claims.Audience[0]
	}
	return ""
}

// IsPerson returns true if the token represents a person (UniqueID matches SCIPER pattern)
func IsPerson(claims *UnifiedClaims) bool {
	if claims.UniqueID == "" {
		return false
	}
	// SCIPER pattern: exactly 6 digits
	matched, _ := regexp.MatchString(`^\d{6}$`, claims.UniqueID)
	return matched
}

// IsService returns true if the token represents a service account (UniqueID matches M+5digits pattern)
func IsService(claims *UnifiedClaims) bool {
	if claims.UniqueID == "" {
		return false // Neither person nor service if no UniqueID
	}
	// Service account pattern: M followed by exactly 5 digits (e.g., M02575)
	matched, _ := regexp.MatchString(`^M\d{5}$`, claims.UniqueID)
	return matched
}

// GetUserType returns the user type based on UniqueID pattern: "person", "service", or "unknown"
func GetUserType(claims *UnifiedClaims) string {
	if IsPerson(claims) {
		return "person"
	}
	if IsService(claims) {
		return "service"
	}
	// Fallback for unknown types (e.g., tokens without UniqueID or non-standard patterns)
	return "unknown"
}

func getJwks(jwksURL string) (string, error) {
	// get JWKS from URL
	resp, err := http.Get(jwksURL)
	if err != nil {
		return "", errors.New("Failed to get JWKS: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Failed to get JWKS: statusCode " + resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("Failed to get JWKS: ReadAll " + err.Error())
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
		validator.hmac = NewHMACValidator(config.Secret, logger)
	}

	// Initialize JWKS validator if JWKS config is provided
	if config.JWKSConfig != nil {
		validator.jwks = NewJWKSValidator(
			config.JWKSConfig.BaseURL,
			config.JWKSConfig.TenantID,
			config.JWKSConfig.KeyCacheTTL,
			logger,
		)
	}

	// Ensure at least one validator is configured
	if validator.hmac == nil && validator.jwks == nil {
		return nil, fmt.Errorf("at least one validation method must be configured (HMAC or JWKS)")
	}

	return validator, nil
}

// determineValidationMethod determines which validation method to use based on the token's algorithm
func (v *GenericValidator) determineValidationMethod(token *jwt.Token) ValidationMethod {
	if alg, ok := token.Header["alg"].(string); ok {
		switch {
		case strings.HasPrefix(alg, "HS"):
			return ValidationHMAC
		case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "ES"):
			return ValidationJWKS
		}
	}
	// Fallback to configured method
	return v.config.Method
}

// ValidateToken validates a token using the appropriate validation method
func (v *GenericValidator) ValidateToken(tokenString string) (*UnifiedClaims, error) {
	// Parse header without validation to determine signing method
	header, err := parseJWTHeader(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token header: %w", err)
	}

	// Create a dummy token to determine validation method
	dummyToken := &jwt.Token{Header: header}
	method := v.determineValidationMethod(dummyToken)

	// Validate using appropriate validator
	switch method {
	case ValidationHMAC:
		if v.hmac == nil {
			return nil, fmt.Errorf("HMAC validation requested but not configured")
		}
		return v.hmac.ValidateToken(tokenString)
	case ValidationJWKS:
		if v.jwks == nil {
			return nil, fmt.Errorf("JWKS validation requested but not configured")
		}
		return v.jwks.ValidateToken(tokenString)
	default:
		return nil, fmt.Errorf("unsupported validation method: %s", method)
	}
}
