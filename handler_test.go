package forwardauth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandler(t *testing.T) {
	config := &Config{
		SessionEnabled:    true,
		PasswordEnabled:   true,
		ValidPasswords:    []string{"SECRET"},
		HeaderAuthEnabled: true,
		HeaderAuthCheckFunc: func(phone, mail string) bool {
			return true
		},
		StepUpEnabled: true,
		StepUpPaths:   []string{"/admin/*"},
	}

	handler := NewHandler(config)

	require.NotNil(t, handler)
	assert.NotNil(t, handler.config)
	assert.NotNil(t, handler.stepUpMatcher)
	assert.Len(t, handler.checkers, 3) // password, header, session

	// Verify checkers are sorted by priority
	assert.Equal(t, "password", handler.checkers[0].Name())
	assert.Equal(t, "header", handler.checkers[1].Name())
	assert.Equal(t, "session", handler.checkers[2].Name())
}

func TestHandlerCheck_PasswordAuth(t *testing.T) {
	config := &Config{
		PasswordEnabled: true,
		PasswordHeader:  "Stargate-Password",
		ValidPasswords:  []string{"SECRET"},
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.headers["Stargate-Password"] = "secret"

	result, err := handler.Check(ctx, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
	assert.Equal(t, AuthMethodPassword, result.AuthMethod)
}

func TestHandlerCheck_SessionAuth(t *testing.T) {
	config := &Config{
		SessionEnabled: true,
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	sess.Set(KeyUserID, "user-123")
	sess.Set(KeyUserMail, "user@example.com")

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
	assert.Equal(t, AuthMethodSession, result.AuthMethod)
	assert.Equal(t, "user-123", result.UserID)
	assert.Equal(t, "user@example.com", result.Email)
}

func TestHandlerCheck_NotAuthenticated(t *testing.T) {
	config := &Config{
		SessionEnabled: true,
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	sess := newMockSession()

	result, err := handler.Check(ctx, sess)

	require.Error(t, err)
	assert.Equal(t, ErrNotAuthenticated, err)
	assert.Nil(t, result)
}

func TestHandlerCheck_StepUpRequired(t *testing.T) {
	config := &Config{
		SessionEnabled:   true,
		StepUpEnabled:    true,
		StepUpPaths:      []string{"/admin/*"},
		StepUpSessionKey: "step_up_verified",
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.path = "/admin/settings"
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	// step_up_verified is not set

	result, err := handler.Check(ctx, sess)

	require.Error(t, err)
	assert.Equal(t, ErrStepUpRequired, err)
	assert.Nil(t, result)
}

func TestHandlerCheck_StepUpVerified(t *testing.T) {
	config := &Config{
		SessionEnabled:   true,
		StepUpEnabled:    true,
		StepUpPaths:      []string{"/admin/*"},
		StepUpSessionKey: "step_up_verified",
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.path = "/admin/settings"
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	sess.Set("step_up_verified", true)

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
}

func TestHandlerCheck_StepUpRequiredWhenSessionNil(t *testing.T) {
	config := &Config{
		HeaderAuthEnabled:   true,
		HeaderAuthUserPhone: "X-User-Phone",
		HeaderAuthCheckFunc: func(phone, mail string) bool { return true },
		StepUpEnabled:       true,
		StepUpPaths:         []string{"/admin/*"},
		StepUpSessionKey:    "step_up_verified",
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.path = "/admin/settings"
	ctx.headers["X-User-Phone"] = "1234567890"
	// No session - header auth passes but step-up requires session

	result, err := handler.Check(ctx, nil)

	require.Error(t, err)
	assert.Equal(t, ErrStepUpRequired, err)
	assert.Nil(t, result)
}

func TestHandlerCheck_StepUpNotRequiredForPath(t *testing.T) {
	config := &Config{
		SessionEnabled:   true,
		StepUpEnabled:    true,
		StepUpPaths:      []string{"/admin/*"},
		StepUpSessionKey: "step_up_verified",
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.path = "/public/page"
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	// step_up_verified is not set, but not required for this path

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
}

func TestHandlerSetAuthHeaders(t *testing.T) {
	config := &Config{
		UserHeaderName:   "X-Forwarded-User",
		AuthUserHeader:   "X-Auth-User",
		AuthEmailHeader:  "X-Auth-Email",
		AuthScopesHeader: "X-Auth-Scopes",
		AuthRoleHeader:   "X-Auth-Role",
		AuthAMRHeader:    "X-Auth-AMR",
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	result := &AuthResult{
		Authenticated: true,
		UserID:        "user-123",
		Email:         "user@example.com",
		Scopes:        []string{"read", "write"},
		Role:          "admin",
		AMR:           []string{"otp", "mfa"},
	}

	handler.SetAuthHeaders(ctx, result)

	assert.Equal(t, "user-123", ctx.respHdrs["X-Forwarded-User"])
	assert.Equal(t, "user-123", ctx.respHdrs["X-Auth-User"])
	assert.Equal(t, "user@example.com", ctx.respHdrs["X-Auth-Email"])
	assert.Equal(t, "read,write", ctx.respHdrs["X-Auth-Scopes"])
	assert.Equal(t, "admin", ctx.respHdrs["X-Auth-Role"])
	assert.Equal(t, "otp,mfa", ctx.respHdrs["X-Auth-AMR"])
}

func TestHandlerSetAuthHeaders_NoUserID(t *testing.T) {
	config := &Config{
		UserHeaderName: "X-Forwarded-User",
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	result := &AuthResult{
		Authenticated: true,
	}

	handler.SetAuthHeaders(ctx, result)

	assert.Equal(t, "authenticated", ctx.respHdrs["X-Forwarded-User"])
}

func TestHandlerAddChecker(t *testing.T) {
	handler := NewHandler(&Config{})

	// Clear default checkers
	handler.checkers = nil

	// Add checkers in wrong order
	handler.AddChecker(NewSessionChecker(&Config{}))  // priority 30
	handler.AddChecker(NewPasswordChecker(&Config{})) // priority 10
	handler.AddChecker(NewHeaderChecker(&Config{}))   // priority 20

	// Verify they are sorted by priority
	assert.Len(t, handler.checkers, 3)
	assert.Equal(t, "password", handler.checkers[0].Name())
	assert.Equal(t, "header", handler.checkers[1].Name())
	assert.Equal(t, "session", handler.checkers[2].Name())
}

func TestHandlerGetStepUpMatcher(t *testing.T) {
	config := &Config{
		StepUpEnabled: true,
		StepUpPaths:   []string{"/admin/*"},
	}
	handler := NewHandler(config)

	matcher := handler.GetStepUpMatcher()

	require.NotNil(t, matcher)
	assert.True(t, matcher.IsEnabled())
	assert.Equal(t, 1, matcher.PatternCount())
}

func TestHandlerGetConfig(t *testing.T) {
	config := &Config{
		AuthHost:  "auth.example.com",
		LoginPath: "/login",
	}
	handler := NewHandler(config)

	got := handler.GetConfig()

	assert.Equal(t, "auth.example.com", got.AuthHost)
	assert.Equal(t, "/login", got.LoginPath)
}

func TestHandlerCheck_HeaderAuth(t *testing.T) {
	config := &Config{
		HeaderAuthEnabled:   true,
		HeaderAuthUserPhone: "X-User-Phone",
		HeaderAuthUserMail:  "X-User-Mail",
		HeaderAuthCheckFunc: func(phone, mail string) bool {
			return phone == "1234567890" || mail == "user@example.com"
		},
		HeaderAuthGetInfoFunc: func(phone, mail string) *UserInfo {
			return &UserInfo{
				UserID: "user-123",
				Email:  mail,
				Phone:  phone,
				Scopes: []string{"read", "write"},
				Role:   "admin",
			}
		},
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.headers["X-User-Phone"] = "1234567890"

	result, err := handler.Check(ctx, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
	assert.Equal(t, AuthMethodHeader, result.AuthMethod)
	assert.Equal(t, "user-123", result.UserID)
}

func TestHandlerCheck_MultipleCheckers(t *testing.T) {
	config := &Config{
		PasswordEnabled: true,
		PasswordHeader:  "X-Password",
		ValidPasswords:  []string{"WRONG"}, // This should fail
		SessionEnabled:  true,
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.headers["X-Password"] = "incorrect"

	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	sess.Set(KeyUserID, "session-user")

	// Password fails, but session should succeed
	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
	assert.Equal(t, AuthMethodSession, result.AuthMethod)
	assert.Equal(t, "session-user", result.UserID)
}

func TestHandlerCheck_AuthRefresh(t *testing.T) {
	refreshCalled := false
	config := &Config{
		SessionEnabled:      true,
		HeaderAuthEnabled:   true,
		AuthRefreshEnabled:  true,
		AuthRefreshInterval: 1 * time.Minute,
		HeaderAuthCheckFunc: func(phone, mail string) bool {
			return true
		},
		HeaderAuthGetInfoFunc: func(phone, mail string) *UserInfo {
			refreshCalled = true
			return &UserInfo{
				UserID: "refreshed-user",
				Scopes: []string{"new-scope"},
				Role:   "new-role",
			}
		},
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	sess.Set(KeyUserPhone, "1234567890")
	// Set old refresh time to trigger refresh
	sess.Set(KeyAuthRefreshedAt, time.Now().Add(-10*time.Minute).Unix())

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
	assert.True(t, refreshCalled)
	assert.Equal(t, []string{"new-scope"}, result.Scopes)
	assert.Equal(t, "new-role", result.Role)
}

func TestHandlerCheck_AuthRefreshNoIdentifiers(t *testing.T) {
	config := &Config{
		SessionEnabled:      true,
		AuthRefreshEnabled:  true,
		AuthRefreshInterval: 1 * time.Minute,
		HeaderAuthGetInfoFunc: func(phone, mail string) *UserInfo {
			return nil
		},
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	// No phone or mail set - refresh should be skipped

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
}

func TestHandlerCheck_AuthRefreshFailed(t *testing.T) {
	config := &Config{
		SessionEnabled:      true,
		HeaderAuthEnabled:   true,
		AuthRefreshEnabled:  true,
		AuthRefreshInterval: 1 * time.Minute,
		HeaderAuthCheckFunc: func(phone, mail string) bool {
			return true
		},
		HeaderAuthGetInfoFunc: func(phone, mail string) *UserInfo {
			return nil // Simulate refresh failure
		},
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	sess.Set(KeyUserMail, "user@example.com")
	sess.Set(KeyAuthRefreshedAt, time.Now().Add(-10*time.Minute).Unix())

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
}

// mockHandlerContext extends mockContext with additional tracking
type mockHandlerContext struct {
	*mockContext
	redirectLocation string
	statusCode       int
	jsonResponse     interface{}
	stringResponse   string
}

func newMockHandlerContext() *mockHandlerContext {
	return &mockHandlerContext{
		mockContext: newMockContext(),
	}
}

func (c *mockHandlerContext) Redirect(location string, status ...int) error {
	c.redirectLocation = location
	if len(status) > 0 {
		c.statusCode = status[0]
	} else {
		c.statusCode = 302
	}
	return nil
}

func (c *mockHandlerContext) Status(status int) Context {
	c.statusCode = status
	return c
}

func (c *mockHandlerContext) JSON(v interface{}) error {
	c.jsonResponse = v
	return nil
}

func (c *mockHandlerContext) SendString(s string) error {
	c.stringResponse = s
	return nil
}

func (c *mockHandlerContext) SendStatus(status int) error {
	c.statusCode = status
	return nil
}

func (c *mockHandlerContext) Context() context.Context {
	return context.Background()
}

func TestHandlerHandleNotAuthenticated_HTML(t *testing.T) {
	config := &Config{
		AuthHost:      "auth.example.com",
		LoginPath:     "/_login",
		CallbackParam: "callback",
	}
	handler := NewHandler(config)

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "text/html"
	ctx.hostname = "app.example.com"
	ctx.protocol = "https"

	err := handler.HandleNotAuthenticated(ctx)

	require.NoError(t, err)
	assert.Contains(t, ctx.redirectLocation, "auth.example.com")
	assert.Contains(t, ctx.redirectLocation, "/_login")
}

func TestHandlerHandleNotAuthenticated_JSON(t *testing.T) {
	config := &Config{
		AuthHost:  "auth.example.com",
		LoginPath: "/_login",
	}
	handler := NewHandler(config)

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "application/json"

	err := handler.HandleNotAuthenticated(ctx)

	require.NoError(t, err)
	assert.Equal(t, 401, ctx.statusCode)
}

func TestHandlerHandleStepUpRequired_HTML(t *testing.T) {
	config := &Config{
		StepUpURL:     "/_step_up",
		CallbackParam: "callback",
		AuthHost:      "auth.example.com",
		LoginPath:     "/_login",
	}
	handler := NewHandler(config)

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "text/html"
	ctx.hostname = "app.example.com"
	ctx.protocol = "https"

	err := handler.HandleStepUpRequired(ctx)

	require.NoError(t, err)
	assert.Contains(t, ctx.redirectLocation, "/_step_up")
}

func TestHandlerHandleStepUpRequired_JSON(t *testing.T) {
	config := &Config{
		StepUpURL: "/_step_up",
	}
	handler := NewHandler(config)

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "application/json"

	err := handler.HandleStepUpRequired(ctx)

	require.NoError(t, err)
	assert.Equal(t, 403, ctx.statusCode)
}

func TestHandlerHandleSessionError(t *testing.T) {
	config := &Config{}
	handler := NewHandler(config)

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "application/json"

	err := handler.HandleSessionError(ctx, ErrSessionStoreError)

	require.NoError(t, err)
	assert.Equal(t, 500, ctx.statusCode)
}

func TestHandlerWithCustomErrorHandler(t *testing.T) {
	customHandlerCalled := false
	config := &Config{
		ErrorHandler: func(c Context, statusCode int, message string) error {
			customHandlerCalled = true
			return c.Status(statusCode).SendString(message)
		},
	}
	handler := NewHandler(config)

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "application/json"

	err := handler.HandleNotAuthenticated(ctx)

	require.NoError(t, err)
	assert.True(t, customHandlerCalled)
}

func TestHandlerWithTranslateFunc(t *testing.T) {
	config := &Config{
		TranslateFunc: func(c Context, key string) string {
			translations := map[string]string{
				"error.auth_required":    "请先登录",
				"error.step_up_required": "需要二次验证",
			}
			if v, ok := translations[key]; ok {
				return v
			}
			return key
		},
	}
	handler := NewHandler(config)

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "application/json"

	err := handler.HandleNotAuthenticated(ctx)
	require.NoError(t, err)

	err = handler.HandleStepUpRequired(ctx)
	require.NoError(t, err)
}

func TestHandlerWithLogger(t *testing.T) {
	// Create a mock logger
	logger := &mockLogger{}
	config := &Config{
		SessionEnabled: true,
		Logger:         logger,
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Authenticated)
}

func TestHandlerCheck_LoggerOnCheckerFailure(t *testing.T) {
	logger := &mockLogger{}
	config := &Config{
		PasswordEnabled: true,
		PasswordHeader:  "X-Password",
		ValidPasswords:  []string{"SECRET"},
		Logger:          logger,
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.headers["X-Password"] = "wrong"

	_, err := handler.Check(ctx, nil)

	require.Error(t, err)
	assert.Equal(t, ErrInvalidPassword, err)
	assert.Contains(t, logger.messages, "Auth checker failed")
}

func TestHandlerCheck_LoggerOnAuthSuccess(t *testing.T) {
	logger := &mockLogger{}
	config := &Config{
		SessionEnabled: true,
		Logger:         logger,
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, logger.messages, "Authentication successful")
}

func TestHandlerCheck_AuthRefreshSaveError(t *testing.T) {
	logger := &mockLogger{}
	config := &Config{
		SessionEnabled:      true,
		AuthRefreshEnabled:  true,
		AuthRefreshInterval: 1 * time.Minute,
		HeaderAuthGetInfoFunc: func(phone, mail string) *UserInfo {
			return &UserInfo{
				UserID: "user-123",
				Scopes: []string{"scope1"},
				Role:   "admin",
			}
		},
		Logger: logger,
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	sess := &mockSessionWithSaveError{data: map[string]interface{}{
		KeyAuthenticated:   true,
		KeyUserPhone:       "1234567890",
		KeyAuthRefreshedAt: time.Now().Add(-10 * time.Minute).Unix(),
	}}

	result, err := handler.Check(ctx, sess)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, logger.messages, "Failed to save session after auth refresh")
}

func TestHandlerHandleSessionError_WithTranslateFuncAndLogger(t *testing.T) {
	logger := &mockLogger{}
	config := &Config{
		TranslateFunc: func(c Context, key string) string {
			if key == "error.session_store_failed" {
				return "会话存储失败"
			}
			return key
		},
		Logger: logger,
	}
	handler := NewHandler(config)

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "application/json"

	err := handler.HandleSessionError(ctx, ErrSessionStoreError)

	require.NoError(t, err)
	assert.Equal(t, 500, ctx.statusCode)
	assert.Contains(t, logger.messages, "Session store error")
}

// mockSessionWithSaveError implements Session but Save returns error
type mockSessionWithSaveError struct {
	data map[string]interface{}
}

func (s *mockSessionWithSaveError) Get(key string) interface{}        { return s.data[key] }
func (s *mockSessionWithSaveError) Set(key string, value interface{}) { s.data[key] = value }
func (s *mockSessionWithSaveError) Delete(key string)                 { delete(s.data, key) }
func (s *mockSessionWithSaveError) Save() error                       { return ErrSessionStoreError }
func (s *mockSessionWithSaveError) Destroy() error                    { return nil }
func (s *mockSessionWithSaveError) ID() string                        { return "test-id" }

// mockLogger implements Logger interface for testing
type mockLogger struct {
	messages []string
}

func (l *mockLogger) Debug() LogEvent { return &mockLogEvent{logger: l} }
func (l *mockLogger) Info() LogEvent  { return &mockLogEvent{logger: l} }
func (l *mockLogger) Warn() LogEvent  { return &mockLogEvent{logger: l} }
func (l *mockLogger) Error() LogEvent { return &mockLogEvent{logger: l} }

type mockLogEvent struct {
	logger *mockLogger
}

func (e *mockLogEvent) Str(key, val string) LogEvent               { return e }
func (e *mockLogEvent) Bool(key string, val bool) LogEvent         { return e }
func (e *mockLogEvent) Int(key string, val int) LogEvent           { return e }
func (e *mockLogEvent) Int64(key string, val int64) LogEvent       { return e }
func (e *mockLogEvent) Dur(key string, val time.Duration) LogEvent { return e }
func (e *mockLogEvent) Err(err error) LogEvent                     { return e }
func (e *mockLogEvent) Msg(msg string) {
	e.logger.messages = append(e.logger.messages, msg)
}
