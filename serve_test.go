package forwardauth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServeAuthenticatedSetsHeadersAnd200(t *testing.T) {
	handler := NewHandler(&Config{SessionEnabled: true})

	ctx := newMockHandlerContext()
	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	sess.Set(KeyUserID, "user-1")
	sess.Set(KeyUserRole, "admin")

	require.NoError(t, handler.Serve(ctx, sess))

	assert.Equal(t, 200, ctx.statusCode)
	assert.Equal(t, "user-1", ctx.respHdrs["X-Forwarded-User"])
	assert.Equal(t, "user-1", ctx.respHdrs["X-Auth-User"])
	assert.Equal(t, "admin", ctx.respHdrs["X-Auth-Role"])
}

func TestServeUnauthenticatedRedirectsHTML(t *testing.T) {
	handler := NewHandler(&Config{
		SessionEnabled: true,
		AuthHost:       "auth.example.com",
	})

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "text/html"

	require.NoError(t, handler.Serve(ctx, nil))

	assert.Equal(t, 302, ctx.statusCode)
	assert.Contains(t, ctx.redirectLocation, "auth.example.com/_login")
}

func TestServeStepUpRequiredRedirectsToStepUpURL(t *testing.T) {
	handler := NewHandler(&Config{
		SessionEnabled:            true,
		StepUpEnabled:             true,
		StepUpPaths:               []string{"/admin/*"},
		StepUpForwardedURITrusted: true,
		AuthHost:                  "auth.example.com",
	})

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "text/html"
	ctx.headers["X-Forwarded-Uri"] = "/admin/settings"

	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	sess.Set(KeyUserID, "user-1")

	require.NoError(t, handler.Serve(ctx, sess))

	assert.Equal(t, 302, ctx.statusCode)
	assert.Contains(t, ctx.redirectLocation, "/_step_up")
}

// wrappingChecker is what a caller writes to say which of its checks refused,
// which is the ordinary use of %w.
type wrappingChecker struct{ err error }

func (c wrappingChecker) Check(Context, Session) (*AuthResult, error) {
	return nil, fmt.Errorf("directory check: %w", c.err)
}
func (wrappingChecker) Priority() int { return 1 }
func (wrappingChecker) Name() string  { return "wrapping" }

// A wrapped ErrStepUpRequired means step-up as plainly as a bare one. Compared
// by identity it fell through to the login redirect -- the one answer that
// cannot resolve it, because the user is already authenticated.
func TestHandleCheckErrorUnwrapsSentinels(t *testing.T) {
	handler := NewHandler(&Config{
		SessionEnabled: false,
		StepUpURL:      "/_step_up",
		AuthHost:       "auth.example.com",
	})
	handler.AddChecker(wrappingChecker{err: ErrStepUpRequired})

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "text/html"

	require.NoError(t, handler.Serve(ctx, nil))

	assert.Contains(t, ctx.redirectLocation, "/_step_up")
}

func TestHandleCheckErrorWrappedNotAuthenticated(t *testing.T) {
	handler := NewHandler(&Config{AuthHost: "auth.example.com"})

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "text/html"

	require.NoError(t, handler.HandleCheckError(ctx, fmt.Errorf("session: %w", ErrNotAuthenticated)))

	assert.Contains(t, ctx.redirectLocation, "/_login")
}

func TestServeWithStoreNilStoreMeansNoSession(t *testing.T) {
	handler := NewHandler(&Config{
		PasswordEnabled: true,
		PasswordHeader:  "X-Auth-Password",
		ValidPasswords:  []string{"SECRET123"},
	})

	ctx := newMockHandlerContext()
	ctx.headers["X-Auth-Password"] = "secret123"

	require.NoError(t, handler.ServeWithStore(ctx, nil))

	assert.Equal(t, 200, ctx.statusCode)
	assert.Equal(t, "authenticated", ctx.respHdrs["X-Forwarded-User"])
}

func TestServeWithStoreReportsStoreFailure(t *testing.T) {
	handler := NewHandler(&Config{SessionEnabled: true})

	store := SessionStoreFunc(func(Context) (Session, error) {
		return nil, errors.New("backend down")
	})

	ctx := newMockHandlerContext()
	ctx.headers["Accept"] = "application/json"

	require.NoError(t, handler.ServeWithStore(ctx, store))

	assert.Equal(t, 500, ctx.statusCode)
}

func TestSessionStoreFuncGet(t *testing.T) {
	sess := newMockSession()
	var got Context

	store := SessionStoreFunc(func(c Context) (Session, error) {
		got = c
		return sess, nil
	})

	ctx := newMockContext()
	returned, err := store.Get(ctx)

	require.NoError(t, err)
	assert.Same(t, sess, returned)
	assert.Same(t, ctx, got)
}

// The store's session is the one the checks see.
func TestServeWithStoreUsesStoreSession(t *testing.T) {
	handler := NewHandler(&Config{SessionEnabled: true})

	sess := newMockSession()
	sess.Set(KeyAuthenticated, true)
	sess.Set(KeyUserID, "user-1")

	ctx := newMockHandlerContext()
	require.NoError(t, handler.ServeWithStore(ctx, SessionStoreFunc(func(Context) (Session, error) {
		return sess, nil
	})))

	assert.Equal(t, 200, ctx.statusCode)
	assert.Equal(t, "user-1", ctx.respHdrs["X-Auth-User"])
}
