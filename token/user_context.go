package token

// UserContext holds information about the user extracted from the JWT token
type UserContext struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"` // "person", "service", or "unknown"
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	TenantID string   `json:"tenant_id"`
}
