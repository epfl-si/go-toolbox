package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// 3.1 Permission Operations
// ============================================================================

func TestPermission_String(t *testing.T) {
	tests := []struct {
		name       string
		permission Permission
		want       string
	}{
		{
			name:       "app:read",
			permission: Permission{Resource: "app", Action: "read"},
			want:       "app:read",
		},
		{
			name:       "app:write",
			permission: Permission{Resource: "app", Action: "write"},
			want:       "app:write",
		},
		{
			name:       "system:admin",
			permission: Permission{Resource: "system", Action: "admin"},
			want:       "system:admin",
		},
		{
			name:       "secret:delete",
			permission: Permission{Resource: "secret", Action: "delete"},
			want:       "secret:delete",
		},
		{
			name:       "unit:read",
			permission: Permission{Resource: "unit", Action: "read"},
			want:       "unit:read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.permission.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPermission_Equals(t *testing.T) {
	tests := []struct {
		name string
		p1   Permission
		p2   Permission
		want bool
	}{
		{
			name: "matching permissions",
			p1:   Permission{Resource: "app", Action: "read"},
			p2:   Permission{Resource: "app", Action: "read"},
			want: true,
		},
		{
			name: "non-matching resource",
			p1:   Permission{Resource: "app", Action: "read"},
			p2:   Permission{Resource: "unit", Action: "read"},
			want: false,
		},
		{
			name: "non-matching action",
			p1:   Permission{Resource: "app", Action: "read"},
			p2:   Permission{Resource: "app", Action: "write"},
			want: false,
		},
		{
			name: "both different",
			p1:   Permission{Resource: "app", Action: "read"},
			p2:   Permission{Resource: "system", Action: "admin"},
			want: false,
		},
		{
			name: "system:admin matching",
			p1:   Permission{Resource: "system", Action: "admin"},
			p2:   Permission{Resource: "system", Action: "admin"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p1.Equals(tt.p2)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPermission_PredefinedConstants(t *testing.T) {
	tests := []struct {
		name       string
		permission Permission
		wantRes    string
		wantAction string
	}{
		{
			name:       "AppCreate",
			permission: AppCreate,
			wantRes:    "app",
			wantAction: "create",
		},
		{
			name:       "AppRead",
			permission: AppRead,
			wantRes:    "app",
			wantAction: "read",
		},
		{
			name:       "AppModify",
			permission: AppModify,
			wantRes:    "app",
			wantAction: "modify",
		},
		{
			name:       "AppDelete",
			permission: AppDelete,
			wantRes:    "app",
			wantAction: "delete",
		},
		{
			name:       "AppAdmin",
			permission: AppAdmin,
			wantRes:    "app",
			wantAction: "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantRes, tt.permission.Resource)
			assert.Equal(t, tt.wantAction, tt.permission.Action)

			// Verify String() method also works correctly
			expectedString := tt.wantRes + ":" + tt.wantAction
			assert.Equal(t, expectedString, tt.permission.String())
		})
	}
}

func TestPermission_PredefinedConstantsEquality(t *testing.T) {
	// Test that predefined constants can be compared with Equals
	appReadDuplicate := Permission{Resource: "app", Action: "read"}
	assert.True(t, AppRead.Equals(appReadDuplicate))
	assert.False(t, AppRead.Equals(AppCreate))
	assert.False(t, AppCreate.Equals(AppDelete))
}
