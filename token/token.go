// Package token handles JWT tokens manipulation
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
	"time"

	keyfunc "github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// Authenticater is the interface that wraps the Authenticate method
type Authenticater interface {
	Authenticate(login, pass string) (CustomClaims, error)
}

// CustomClaims is the struct that represents the claims of a JWT token in EPFL context
// Deprecated: Use UnifiedClaims for new implementations
type CustomClaims struct {
	Sciper string `json:"sciper"`
	jwt.RegisteredClaims
}

// Unit represents an EPFL organizational unit with its hierarchy information
type Unit struct {
	ID       string   `json:"id"`       // Unit ID (numeric string)
	Name     string   `json:"name"`     // Display name
	CF       string   `json:"cf"`       // Cost center identifier
	Path     string   `json:"path"`     // Hierarchical path
	Children []string `json:"children"` // List of child unit IDs
}

// UnifiedClaims supports both local HMAC and Entra JWKS token formats
type UnifiedClaims struct {
	// Core identifiers
	UniqueID string `json:"uniqueid,omitempty"` // SCIPER (6 digits) or service account (M + 5 digits)
	Name     string `json:"name,omitempty"`     // Display name
	Email    string `json:"email,omitempty"`    // Primary email address
	TenantID string `json:"tid,omitempty"`      // Azure Entra tenant ID

	// Authorization
	Groups []string `json:"groups,omitempty"` // Group memberships
	Scopes []string `json:"scopes,omitempty"` // Token scopes
	Units  []Unit   `json:"units,omitempty"`  // EPFL unit info with hierarchy
	Roles  []string `json:"roles,omitempty"`  // User roles

	jwt.RegisteredClaims // Standard JWT claims (iss, sub, exp, etc.)
}

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

// JWKSCache represents a simple in-memory cache for JWKS keys
type JWKSCache struct {
	keys map[string]*CachedKey
}

// CachedKey represents a cached JWKS key with expiration
type CachedKey struct {
	Key       keyfunc.Keyfunc
	ExpiresAt time.Time
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

// Token is the struct that represents a JWT token
type Token struct {
	JWT *jwt.Token
}

// New creates a new JWT token
func New(claims CustomClaims) *Token {
	jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return &Token{JWT: jwt}
}

// Parse parses a JWT token
func Parse(tokenString string, secret []byte) (*Token, error) {
	t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is the one expected:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	return &Token{t}, nil
}

// Sign signs a JWT token
func (t *Token) Sign(secret []byte) (string, error) {
	return t.JWT.SignedString([]byte(secret))
}

// Claims returns the claims of a JWT token
func (t *Token) Claims() jwt.MapClaims {
	return t.JWT.Claims.(jwt.MapClaims)
}

// Set sets a claim in a JWT token
func (t *Token) Set(key string, value interface{}) {
	t.Claims()[key] = value
}

// Get gets a claim from a JWT token
func (t *Token) Get(key string) interface{} {
	return t.Claims()[key]
}

// GetString gets a claim from a JWT token as a string
func (t *Token) GetString(key string) string {
	return t.Claims()[key].(string)
}

// ToJSON converts a JWT token to JSON
func (t *Token) ToJSON() (string, error) {
	return t.JWT.Raw, nil
}

// PostLoginHandler is the handler that checks the login and password and returns a JWT token
func PostLoginHandler(log *zap.Logger, auth Authenticater, secret []byte) gin.HandlerFunc {
	log.Info("Creating login handler")
	return func(c *gin.Context) {
		login := c.PostForm("login")
		pass := c.PostForm("pass")

		log.Info("Login attempt", zap.String("login", login))

		claims, err := auth.Authenticate(login, pass)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		t := New(claims)
		encoded, err := t.Sign(secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"access_token": encoded})
	}
}

// parseTokenHeader parses the JWT header part without validation
func parseTokenHeader(tokenString string) (map[string]interface{}, error) {
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
	return &JWKSValidator{
		baseURL:  baseURL,
		tenantID: tenantID,
		keyCache: &JWKSCache{
			keys: make(map[string]*CachedKey),
		},
		cacheTTL: cacheTTL,
		logger:   logger,
	}
}

// ValidateToken validates a token using JWKS
func (v *JWKSValidator) ValidateToken(tokenString string) (*UnifiedClaims, error) {
	claims := &UnifiedClaims{}

	// Parse header without validation to determine signing method
	header, err := parseTokenHeader(tokenString)
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
	if aud, ok := tempClaims["aud"].(string); ok {
		jwksURL += fmt.Sprintf("?appid=%s", aud)
	}

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
	return func(_ *jwt.Token) (interface{}, error) {
		// Check cache
		if cachedKey, exists := v.keyCache.keys[jwksURL]; exists {
			if time.Now().Before(cachedKey.ExpiresAt) {
				return cachedKey.Key, nil
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

		// Cache the key
		v.keyCache.keys[jwksURL] = &CachedKey{
			Key:       jwks,
			ExpiresAt: time.Now().Add(v.cacheTTL),
		}

		return jwks, nil
	}, nil
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
	header, err := parseTokenHeader(tokenString)
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

// MiddlewareConfig defines configuration for the JWT middleware
type MiddlewareConfig struct {
	Validator   TokenValidator // Token validator implementation
	Logger      *zap.Logger    // Logger instance
	ContextKey  string         // Key for storing claims in context (default: "claims")
	HeaderName  string         // Authorization header name (default: "Authorization")
	TokenPrefix string         // Token prefix in header (default: "Bearer ")
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig(validator TokenValidator, logger *zap.Logger) MiddlewareConfig {
	return MiddlewareConfig{
		Validator:   validator,
		Logger:      logger,
		ContextKey:  "claims",
		HeaderName:  "Authorization",
		TokenPrefix: "Bearer ",
	}
}

// UnifiedJWTMiddleware creates middleware that handles JWT token validation
func UnifiedJWTMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.ContextKey == "" {
		config.ContextKey = "claims"
	}
	if config.HeaderName == "" {
		config.HeaderName = "Authorization"
	}
	if config.TokenPrefix == "" {
		config.TokenPrefix = "Bearer "
	}

	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader(config.HeaderName)
		if authHeader == "" {
			config.Logger.Debug("Missing authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authorization header missing",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, config.TokenPrefix)
		if tokenString == authHeader {
			config.Logger.Debug("Invalid token format", zap.String("header", authHeader))
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": fmt.Sprintf("token must start with %s", config.TokenPrefix),
			})
			c.Abort()
			return
		}

		// Validate token
		start := time.Now()
		claims, err := config.Validator.ValidateToken(tokenString)
		duration := time.Since(start)

		if err != nil {
			config.Logger.Debug("Token validation failed",
				zap.Error(err),
				zap.Duration("duration", duration))
			c.JSON(http.StatusUnauthorized, gin.H{"error": err})
			c.Abort()
			return
		}

		config.Logger.Debug("Token validation successful",
			zap.String("user_id", GetUserID(claims)),
			zap.String("user_type", GetUserType(claims)),
			zap.Duration("duration", duration))

		// Set unified claims and user info in context
		c.Set(config.ContextKey, claims)
		c.Set("user_id", GetUserID(claims))
		c.Set("user_type", GetUserType(claims))
		c.Set("user_email", claims.Email)

		c.Next()
	}
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

// ToUnifiedClaims converts CustomClaims to UnifiedClaims for backward compatibility
func (c CustomClaims) ToUnifiedClaims() UnifiedClaims {
	return UnifiedClaims{
		UniqueID:         c.Sciper, // Map sciper to uniqueid
		RegisteredClaims: c.RegisteredClaims,
	}
}

// ToCustomClaims converts UnifiedClaims to CustomClaims for backward compatibility
func (u UnifiedClaims) ToCustomClaims() CustomClaims {
	return CustomClaims{
		Sciper:           u.UniqueID, // Map uniqueid back to sciper
		RegisteredClaims: u.RegisteredClaims,
	}
}

// ParseUnified parses a JWT token into UnifiedClaims
func ParseUnified(tokenString string, secret []byte) (*UnifiedClaims, error) {
	claims := &UnifiedClaims{}
	t, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if !t.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return claims, nil
}

// NewUnified creates a new JWT token with UnifiedClaims
func NewUnified(claims UnifiedClaims) *Token {
	jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return &Token{JWT: jwt}
}

func GetJwtDataFromHeader(authorizationHeader string) map[string]interface{} {
	rBearerJwt, _ := regexp.Compile(`^Bearer (?:[\w-]*\.){2}[\w-]*$`)
	if rBearerJwt.MatchString(authorizationHeader) {
		authorizationHeader = strings.ReplaceAll(authorizationHeader, "Bearer ", "")

		// get middle part and decode base64
		splits := strings.Split(authorizationHeader, ".")
		if len(splits) != 3 {
			return nil
		}
		// unmarshal jwtData to json
		var data map[string]interface{}
		// decode splits[1] from base64 to json
		dataPart := splits[1]
		// decode base64 part 2 and convert to JSON
		jsonData, err := base64.RawURLEncoding.DecodeString(dataPart)
		if err != nil {
			return nil
		}

		err = json.Unmarshal([]byte(jsonData), &data)
		if err != nil {
			return nil
		}

		return data
	}

	return nil
}

// GinMiddleware is the middleware that checks the JWT token
func GinMiddleware(secret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorizationHeaderString := c.GetHeader("Authorization")
		if authorizationHeaderString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		// Check that the authorization header starts with "Bearer"
		if len(authorizationHeaderString) < 7 || authorizationHeaderString[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract the token from the authorization header
		tokenString := authorizationHeaderString[7:]

		t, err := Parse(tokenString, secret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("token", t)
		c.Next()
	}
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
	header, err := parseTokenHeader(tokenString)
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
