package forwardauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.True(t, cfg.SessionEnabled)
	assert.False(t, cfg.PasswordEnabled)
	assert.Equal(t, "Stargate-Password", cfg.PasswordHeader)
	assert.False(t, cfg.HeaderAuthEnabled)
	assert.Equal(t, "X-User-Phone", cfg.HeaderAuthUserPhone)
	assert.Equal(t, "X-User-Mail", cfg.HeaderAuthUserMail)
	assert.False(t, cfg.StepUpEnabled)
	assert.Equal(t, "/_step_up", cfg.StepUpURL)
	assert.Equal(t, "step_up_verified", cfg.StepUpSessionKey)
	assert.False(t, cfg.AuthRefreshEnabled)
	assert.Equal(t, 5*time.Minute, cfg.AuthRefreshInterval)
	assert.Equal(t, "X-Forwarded-User", cfg.UserHeaderName)
	assert.Equal(t, "X-Auth-User", cfg.AuthUserHeader)
	assert.Equal(t, "X-Auth-Email", cfg.AuthEmailHeader)
	assert.Equal(t, "X-Auth-Scopes", cfg.AuthScopesHeader)
	assert.Equal(t, "X-Auth-Role", cfg.AuthRoleHeader)
	assert.Equal(t, "X-Auth-AMR", cfg.AuthAMRHeader)
	assert.Equal(t, "/_login", cfg.LoginPath)
	assert.Equal(t, "callback", cfg.CallbackParam)
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr error
	}{
		{
			name:    "valid default config",
			config:  DefaultConfig(),
			wantErr: nil,
		},
		{
			name: "password enabled without passwords",
			config: Config{
				PasswordEnabled: true,
			},
			wantErr: ErrNoPasswordConfigured,
		},
		{
			name: "password enabled with passwords",
			config: Config{
				PasswordEnabled: true,
				ValidPasswords:  []string{"password1"},
			},
			wantErr: nil,
		},
		{
			name: "password enabled with check func",
			config: Config{
				PasswordEnabled:   true,
				PasswordCheckFunc: func(p string) bool { return true },
			},
			wantErr: nil,
		},
		{
			name: "header auth enabled without check func",
			config: Config{
				HeaderAuthEnabled: true,
			},
			wantErr: ErrNoUserCheckFunc,
		},
		{
			name: "header auth enabled with check func",
			config: Config{
				HeaderAuthEnabled:   true,
				HeaderAuthCheckFunc: func(phone, mail string) bool { return true },
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()

	assert.Equal(t, "Stargate-Password", cfg.PasswordHeader)
	assert.Equal(t, "X-User-Phone", cfg.HeaderAuthUserPhone)
	assert.Equal(t, "X-User-Mail", cfg.HeaderAuthUserMail)
	assert.Equal(t, "/_step_up", cfg.StepUpURL)
	assert.Equal(t, "step_up_verified", cfg.StepUpSessionKey)
	assert.Equal(t, 5*time.Minute, cfg.AuthRefreshInterval)
	assert.Equal(t, "X-Forwarded-User", cfg.UserHeaderName)
	assert.Equal(t, "X-Auth-User", cfg.AuthUserHeader)
	assert.Equal(t, "X-Auth-Email", cfg.AuthEmailHeader)
	assert.Equal(t, "X-Auth-Scopes", cfg.AuthScopesHeader)
	assert.Equal(t, "X-Auth-Role", cfg.AuthRoleHeader)
	assert.Equal(t, "X-Auth-AMR", cfg.AuthAMRHeader)
	assert.Equal(t, "/_login", cfg.LoginPath)
	assert.Equal(t, "callback", cfg.CallbackParam)
}

func TestConfigApplyDefaultsPreservesExisting(t *testing.T) {
	cfg := &Config{
		PasswordHeader: "Custom-Password",
		UserHeaderName: "X-Custom-User",
		LoginPath:      "/custom-login",
	}
	cfg.ApplyDefaults()

	// Custom values should be preserved
	assert.Equal(t, "Custom-Password", cfg.PasswordHeader)
	assert.Equal(t, "X-Custom-User", cfg.UserHeaderName)
	assert.Equal(t, "/custom-login", cfg.LoginPath)

	// Other defaults should be applied
	assert.Equal(t, "X-User-Phone", cfg.HeaderAuthUserPhone)
	assert.Equal(t, "/_step_up", cfg.StepUpURL)
}

func TestStepUpMatcher(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		patterns []string
		path     string
		want     bool
	}{
		{
			name:     "disabled matcher",
			enabled:  false,
			patterns: []string{"/admin/*"},
			path:     "/admin/users",
			want:     false,
		},
		{
			name:     "empty patterns",
			enabled:  true,
			patterns: []string{},
			path:     "/admin/users",
			want:     false,
		},
		{
			name:     "exact match",
			enabled:  true,
			patterns: []string{"/admin/settings"},
			path:     "/admin/settings",
			want:     true,
		},
		{
			name:     "wildcard match",
			enabled:  true,
			patterns: []string{"/admin/*"},
			path:     "/admin/users",
			want:     true,
		},
		{
			name:     "no match",
			enabled:  true,
			patterns: []string{"/admin/*"},
			path:     "/public/page",
			want:     false,
		},
		{
			name:     "multiple patterns first match",
			enabled:  true,
			patterns: []string{"/admin/*", "/secure/*"},
			path:     "/admin/dashboard",
			want:     true,
		},
		{
			name:     "multiple patterns second match",
			enabled:  true,
			patterns: []string{"/admin/*", "/secure/*"},
			path:     "/secure/data",
			want:     true,
		},
		{
			name:     "deep wildcard",
			enabled:  true,
			patterns: []string{"/api/v1/admin/*"},
			path:     "/api/v1/admin/users/123",
			want:     true,
		},
		{
			name:     "question mark wildcard",
			enabled:  true,
			patterns: []string{"/user/?"},
			path:     "/user/a",
			want:     true,
		},
		{
			name:     "question mark no match",
			enabled:  true,
			patterns: []string{"/user/?"},
			path:     "/user/ab",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewStepUpMatcher(tt.enabled, tt.patterns)
			got := matcher.RequiresStepUp(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStepUpMatcherMethods(t *testing.T) {
	matcher := NewStepUpMatcher(true, []string{"/admin/*", "/secure/*"})

	assert.True(t, matcher.IsEnabled())
	assert.Equal(t, 2, matcher.PatternCount())

	disabledMatcher := NewStepUpMatcher(false, []string{"/admin/*"})
	assert.False(t, disabledMatcher.IsEnabled())
}
