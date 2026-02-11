package forwardauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSession implements the Session interface for testing.
type mockSession struct {
	data map[string]interface{}
}

func newMockSession() *mockSession {
	return &mockSession{data: make(map[string]interface{})}
}

func ptrBool(b bool) *bool {
	return &b
}

func (s *mockSession) Get(key string) interface{} {
	return s.data[key]
}

func (s *mockSession) Set(key string, value interface{}) {
	s.data[key] = value
}

func (s *mockSession) Delete(key string) {
	delete(s.data, key)
}

func (s *mockSession) Save() error {
	return nil
}

func (s *mockSession) Destroy() error {
	s.data = make(map[string]interface{})
	return nil
}

func (s *mockSession) ID() string {
	return "test-session-id"
}

// mockContext implements the Context interface for testing.
type mockContext struct {
	headers  map[string]string
	respHdrs map[string]string
	path     string
	method   string
	protocol string
	hostname string
	query    map[string]string
	locals   map[string]interface{}
}

func newMockContext() *mockContext {
	return &mockContext{
		headers:  make(map[string]string),
		respHdrs: make(map[string]string),
		query:    make(map[string]string),
		locals:   make(map[string]interface{}),
		path:     "/",
		method:   "GET",
		protocol: "https",
		hostname: "example.com",
	}
}

func (c *mockContext) Path() string                                  { return c.path }
func (c *mockContext) Method() string                                { return c.method }
func (c *mockContext) Protocol() string                              { return c.protocol }
func (c *mockContext) Hostname() string                              { return c.hostname }
func (c *mockContext) Get(key string) string                         { return c.headers[key] }
func (c *mockContext) Query(key string) string                       { return c.query[key] }
func (c *mockContext) Set(key, value string)                         { c.respHdrs[key] = value }
func (c *mockContext) SendStatus(status int) error                   { return nil }
func (c *mockContext) Redirect(location string, status ...int) error { return nil }
func (c *mockContext) Status(status int) Context                     { return c }
func (c *mockContext) JSON(v interface{}) error                      { return nil }
func (c *mockContext) SendString(s string) error                     { return nil }
func (c *mockContext) Context() context.Context                      { return context.Background() }

func (c *mockContext) Locals(key string, value ...interface{}) interface{} {
	if len(value) > 0 {
		c.locals[key] = value[0]
		return value[0]
	}
	return c.locals[key]
}

func TestPasswordChecker(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		headerValue string
		wantAuth    bool
		wantErr     error
		wantSkip    bool
	}{
		{
			name: "no password header",
			config: &Config{
				PasswordHeader: "Stargate-Password",
				ValidPasswords: []string{"SECRET"},
			},
			headerValue: "",
			wantSkip:    true,
		},
		{
			name: "valid password",
			config: &Config{
				PasswordHeader: "Stargate-Password",
				ValidPasswords: []string{"SECRET"},
			},
			headerValue: "secret",
			wantAuth:    true,
		},
		{
			name: "invalid password",
			config: &Config{
				PasswordHeader: "Stargate-Password",
				ValidPasswords: []string{"SECRET"},
			},
			headerValue: "wrong",
			wantErr:     ErrInvalidPassword,
		},
		{
			name: "custom check func - valid",
			config: &Config{
				PasswordHeader:    "Stargate-Password",
				PasswordCheckFunc: func(p string) bool { return p == "custom-secret" },
			},
			headerValue: "custom-secret",
			wantAuth:    true,
		},
		{
			name: "custom check func - invalid",
			config: &Config{
				PasswordHeader:    "Stargate-Password",
				PasswordCheckFunc: func(p string) bool { return p == "custom-secret" },
			},
			headerValue: "wrong",
			wantErr:     ErrInvalidPassword,
		},
		{
			name: "custom normalizer - valid",
			config: &Config{
				PasswordHeader: "Stargate-Password",
				PasswordNormalizer: func(p string) string {
					return strings.ToLower(strings.TrimSpace(p))
				},
				ValidPasswords: []string{"lowercase"},
			},
			headerValue: "LowerCase",
			wantAuth:    true,
		},
		{
			name: "custom normalizer - invalid",
			config: &Config{
				PasswordHeader: "Stargate-Password",
				PasswordNormalizer: func(p string) string {
					return strings.ToLower(p)
				},
				ValidPasswords: []string{"expected"},
			},
			headerValue: "wrong",
			wantErr:     ErrInvalidPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewPasswordChecker(tt.config)

			ctx := newMockContext()
			if tt.headerValue != "" {
				ctx.headers[tt.config.PasswordHeader] = tt.headerValue
			}

			result, err := checker.Check(ctx, nil)

			if tt.wantSkip {
				assert.Nil(t, result)
				assert.NoError(t, err)
				return
			}

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantAuth, result.Authenticated)
			assert.Equal(t, AuthMethodPassword, result.AuthMethod)
		})
	}
}

func TestPasswordCheckerPriority(t *testing.T) {
	checker := NewPasswordChecker(&Config{})
	assert.Equal(t, 10, checker.Priority())
	assert.Equal(t, "password", checker.Name())
}

func TestHeaderChecker(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		phone    string
		mail     string
		wantAuth bool
		wantErr  error
		wantSkip bool
	}{
		{
			name: "no headers",
			config: &Config{
				HeaderAuthUserPhone: "X-User-Phone",
				HeaderAuthUserMail:  "X-User-Mail",
				HeaderAuthCheckFunc: func(phone, mail string) bool { return true },
			},
			wantSkip: true,
		},
		{
			name: "valid phone header",
			config: &Config{
				HeaderAuthUserPhone: "X-User-Phone",
				HeaderAuthUserMail:  "X-User-Mail",
				HeaderAuthCheckFunc: func(phone, mail string) bool { return phone == "1234567890" },
			},
			phone:    "1234567890",
			wantAuth: true,
		},
		{
			name: "valid mail header",
			config: &Config{
				HeaderAuthUserPhone: "X-User-Phone",
				HeaderAuthUserMail:  "X-User-Mail",
				HeaderAuthCheckFunc: func(phone, mail string) bool { return mail == "user@example.com" },
			},
			mail:     "user@example.com",
			wantAuth: true,
		},
		{
			name: "user not found",
			config: &Config{
				HeaderAuthUserPhone: "X-User-Phone",
				HeaderAuthUserMail:  "X-User-Mail",
				HeaderAuthCheckFunc: func(phone, mail string) bool { return false },
			},
			phone:   "invalid",
			wantErr: ErrUserNotFound,
		},
		{
			name: "with user info func",
			config: &Config{
				HeaderAuthUserPhone: "X-User-Phone",
				HeaderAuthUserMail:  "X-User-Mail",
				HeaderAuthCheckFunc: func(phone, mail string) bool { return true },
				HeaderAuthGetInfoFunc: func(phone, mail string) *UserInfo {
					return &UserInfo{
						UserID: "user-123",
						Email:  mail,
						Phone:  phone,
						Scopes: []string{"read", "write"},
						Role:   "admin",
					}
				},
			},
			mail:     "user@example.com",
			wantAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewHeaderChecker(tt.config)

			ctx := newMockContext()
			if tt.phone != "" {
				ctx.headers[tt.config.HeaderAuthUserPhone] = tt.phone
			}
			if tt.mail != "" {
				ctx.headers[tt.config.HeaderAuthUserMail] = tt.mail
			}

			result, err := checker.Check(ctx, nil)

			if tt.wantSkip {
				assert.Nil(t, result)
				assert.NoError(t, err)
				return
			}

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantAuth, result.Authenticated)
			assert.Equal(t, AuthMethodHeader, result.AuthMethod)

			// Check user info if available
			if tt.config.HeaderAuthGetInfoFunc != nil {
				assert.Equal(t, "user-123", result.UserID)
				assert.Equal(t, []string{"read", "write"}, result.Scopes)
				assert.Equal(t, "admin", result.Role)
			}
		})
	}
}

func TestHeaderCheckerPriority(t *testing.T) {
	checker := NewHeaderChecker(&Config{})
	assert.Equal(t, 20, checker.Priority())
	assert.Equal(t, "header", checker.Name())
}

func TestSessionChecker(t *testing.T) {
	tests := []struct {
		name             string
		config           *Config
		session          Session // Use interface type to properly handle nil
		wantAuth         bool
		wantErr          error
		wantNeedsRefresh *bool // nil = don't check; true/false = assert
	}{
		{
			name:    "nil session",
			config:  &Config{},
			session: nil, // This is a nil interface
			wantErr: ErrSessionRequired,
		},
		{
			name:    "not authenticated",
			config:  &Config{},
			session: newMockSession(),
			wantErr: ErrNotAuthenticated,
		},
		{
			name:   "authenticated",
			config: &Config{},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, true)
				return s
			}(),
			wantAuth: true,
		},
		{
			name:   "authenticated with user info",
			config: &Config{},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, true)
				s.Set(KeyUserID, "user-123")
				s.Set(KeyUserMail, "user@example.com")
				s.Set(KeyUserPhone, "1234567890")
				s.Set(KeyUserScope, []string{"read", "write"})
				s.Set(KeyUserRole, "admin")
				s.Set(KeyUserAMR, []string{"otp", "mfa"})
				return s
			}(),
			wantAuth: true,
		},
		{
			name: "needs refresh",
			config: &Config{
				AuthRefreshEnabled:  true,
				AuthRefreshInterval: 5 * time.Minute,
			},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, true)
				// Set refresh time to 10 minutes ago
				s.Set(KeyAuthRefreshedAt, time.Now().Add(-10*time.Minute).Unix())
				return s
			}(),
			wantAuth:         true,
			wantNeedsRefresh: ptrBool(true),
		},
		{
			name:   "authenticated value not bool",
			config: &Config{},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, "true") // wrong type
				return s
			}(),
			wantErr: ErrNotAuthenticated,
		},
		{
			name: "needs refresh - nil lastRefreshVal",
			config: &Config{
				AuthRefreshEnabled:  true,
				AuthRefreshInterval: 5 * time.Minute,
			},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, true)
				// KeyAuthRefreshedAt not set
				return s
			}(),
			wantAuth: true,
		},
		{
			name: "needs refresh - invalid lastRefreshVal type",
			config: &Config{
				AuthRefreshEnabled:  true,
				AuthRefreshInterval: 5 * time.Minute,
			},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, true)
				s.Set(KeyAuthRefreshedAt, "invalid") // wrong type
				return s
			}(),
			wantAuth: true,
		},
		{
			name:   "scopes from []interface{}",
			config: &Config{},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, true)
				s.Set(KeyUserScope, []interface{}{"read", "write"})
				return s
			}(),
			wantAuth: true,
		},
		{
			name:   "AMR from []interface{}",
			config: &Config{},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, true)
				s.Set(KeyUserAMR, []interface{}{"otp", "mfa"})
				return s
			}(),
			wantAuth: true,
		},
		{
			name: "no refresh needed - recent",
			config: &Config{
				AuthRefreshEnabled:  true,
				AuthRefreshInterval: 10 * time.Minute,
			},
			session: func() Session {
				s := newMockSession()
				s.Set(KeyAuthenticated, true)
				s.Set(KeyAuthRefreshedAt, time.Now().Unix())
				return s
			}(),
			wantAuth:         true,
			wantNeedsRefresh: ptrBool(false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewSessionChecker(tt.config)

			ctx := newMockContext()
			result, err := checker.Check(ctx, tt.session)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantAuth, result.Authenticated)
			assert.Equal(t, AuthMethodSession, result.AuthMethod)

			// Check user info if set
			if tt.session != nil && tt.session.Get(KeyUserID) != nil {
				assert.Equal(t, "user-123", result.UserID)
				assert.Equal(t, "user@example.com", result.Email)
				assert.Equal(t, "1234567890", result.Phone)
				assert.Equal(t, []string{"read", "write"}, result.Scopes)
				assert.Equal(t, "admin", result.Role)
				assert.Equal(t, []string{"otp", "mfa"}, result.AMR)
			}

			// Check refresh flag
			if tt.wantNeedsRefresh != nil {
				assert.Equal(t, *tt.wantNeedsRefresh, result.NeedsRefresh)
			}
			// Check scopes/AMR from []interface{}
			if tt.name == "scopes from []interface{}" {
				assert.Equal(t, []string{"read", "write"}, result.Scopes)
			}
			if tt.name == "AMR from []interface{}" {
				assert.Equal(t, []string{"otp", "mfa"}, result.AMR)
			}
		})
	}
}

func TestSessionCheckerPriority(t *testing.T) {
	checker := NewSessionChecker(&Config{})
	assert.Equal(t, 30, checker.Priority())
	assert.Equal(t, "session", checker.Name())
}

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"a", "a", true},
		{"abc", "abc", true},
		{"a", "b", false},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"ab", "abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := constantTimeEqual(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInterfaceSliceToStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []interface{}
		want  []string
	}{
		{
			name:  "empty",
			input: []interface{}{},
			want:  []string{},
		},
		{
			name:  "all strings",
			input: []interface{}{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "mixed types",
			input: []interface{}{"a", 1, "b", true},
			want:  []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := interfaceSliceToStrings(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
