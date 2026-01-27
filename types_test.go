package forwardauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthMethodString(t *testing.T) {
	tests := []struct {
		method AuthMethod
		want   string
	}{
		{AuthMethodNone, "none"},
		{AuthMethodSession, "session"},
		{AuthMethodPassword, "password"},
		{AuthMethodHeader, "header"},
		{AuthMethodToken, "token"},
		{AuthMethod(99), "none"}, // Unknown method
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.method.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUserInfoIsActive(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{
			name:   "empty status is active",
			status: "",
			want:   true,
		},
		{
			name:   "active status",
			status: "active",
			want:   true,
		},
		{
			name:   "inactive status",
			status: "inactive",
			want:   false,
		},
		{
			name:   "suspended status",
			status: "suspended",
			want:   false,
		},
		{
			name:   "disabled status",
			status: "disabled",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserInfo{Status: tt.status}
			got := u.IsActive()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthResult(t *testing.T) {
	result := &AuthResult{
		Authenticated: true,
		UserID:        "user-123",
		Email:         "user@example.com",
		Phone:         "1234567890",
		Scopes:        []string{"read", "write"},
		Role:          "admin",
		AMR:           []string{"otp"},
		AuthMethod:    AuthMethodSession,
	}

	assert.True(t, result.Authenticated)
	assert.Equal(t, "user-123", result.UserID)
	assert.Equal(t, "user@example.com", result.Email)
	assert.Equal(t, "1234567890", result.Phone)
	assert.Equal(t, []string{"read", "write"}, result.Scopes)
	assert.Equal(t, "admin", result.Role)
	assert.Equal(t, []string{"otp"}, result.AMR)
	assert.Equal(t, AuthMethodSession, result.AuthMethod)
}

func TestUserInfo(t *testing.T) {
	u := &UserInfo{
		UserID:   "user-123",
		Email:    "user@example.com",
		Phone:    "1234567890",
		Scopes:   []string{"read", "write"},
		Role:     "admin",
		Status:   "active",
		Metadata: map[string]interface{}{"key": "value"},
	}

	assert.Equal(t, "user-123", u.UserID)
	assert.Equal(t, "user@example.com", u.Email)
	assert.Equal(t, "1234567890", u.Phone)
	assert.Equal(t, []string{"read", "write"}, u.Scopes)
	assert.Equal(t, "admin", u.Role)
	assert.Equal(t, "active", u.Status)
	assert.Equal(t, "value", u.Metadata["key"])
	assert.True(t, u.IsActive())
}

func TestSessionKeys(t *testing.T) {
	// Test that session keys are defined correctly
	assert.Equal(t, "authenticated", KeyAuthenticated)
	assert.Equal(t, "user_id", KeyUserID)
	assert.Equal(t, "user_mail", KeyUserMail)
	assert.Equal(t, "user_phone", KeyUserPhone)
	assert.Equal(t, "user_scope", KeyUserScope)
	assert.Equal(t, "user_role", KeyUserRole)
	assert.Equal(t, "user_amr", KeyUserAMR)
	assert.Equal(t, "step_up_verified", KeyStepUpVerified)
	assert.Equal(t, "auth_refreshed_at", KeyAuthRefreshedAt)
}
