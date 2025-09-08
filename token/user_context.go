package token

// UserContext holds information about the user extracted from a JWT token.
// It provides a simplified, application-friendly view of the user's identity.
type UserContext struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"` // "person", "service", or "unknown"
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	TenantID string   `json:"tenant_id"`
}
