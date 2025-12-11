package token

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestExtractBearerTokenFromGinContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		headerValue   string
		expectedToken string
		expectedError string
	}{
		{
			name:          "valid bearer token",
			headerValue:   "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedError: "",
		},
		{
			name:          "valid bearer token with extra spaces",
			headerValue:   "Bearer   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedError: "",
		},
		{
			name:          "missing authorization header",
			headerValue:   "",
			expectedToken: "",
			expectedError: "authorization header missing",
		},
		{
			name:          "bearer without space",
			headerValue:   "BearereyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "",
			expectedError: "authorization header must start with 'Bearer ' (with space)",
		},
		{
			name:          "lowercase bearer",
			headerValue:   "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "",
			expectedError: "authorization header must start with 'Bearer ' (with space)",
		},
		{
			name:          "basic auth instead of bearer",
			headerValue:   "Basic dXNlcjpwYXNz",
			expectedToken: "",
			expectedError: "authorization header must start with 'Bearer ' (with space)",
		},
		{
			name:          "bearer with empty token",
			headerValue:   "Bearer ",
			expectedToken: "",
			expectedError: "bearer token is empty",
		},
		{
			name:          "bearer with only spaces",
			headerValue:   "Bearer    ",
			expectedToken: "",
			expectedError: "bearer token is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test context
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest("GET", "/", nil)

			if tt.headerValue != "" {
				c.Request.Header.Set("Authorization", tt.headerValue)
			}

			// Extract token
			token, err := ExtractBearerTokenFromGinContext(c, "Authorization")

			// Verify results
			assert.Equal(t, tt.expectedToken, token)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
