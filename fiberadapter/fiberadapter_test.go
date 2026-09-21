package fiberadapter_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	forwardauth "github.com/soulteary/forwardauth-kit/v3"
	"github.com/soulteary/forwardauth-kit/v3/fiberadapter"
)

func TestContext(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c fiber.Ctx) error {
		ctx := fiberadapter.NewContext(c)

		// Test basic methods
		assert.Equal(t, "/test", ctx.Path())
		assert.Equal(t, "GET", ctx.Method())
		assert.Contains(t, []string{"http", "https"}, ctx.Protocol())
		assert.NotEmpty(t, ctx.Hostname())

		// Test headers
		assert.Equal(t, "test-value", ctx.Get("X-Test-Header"))
		assert.Equal(t, "", ctx.Get("X-Missing-Header"))

		// Test query
		assert.Equal(t, "value", ctx.Query("param"))
		assert.Equal(t, "", ctx.Query("missing"))

		// Test Set header
		ctx.Set("X-Response-Header", "response-value")

		// Test Locals
		ctx.Locals("key", "local-value")
		assert.Equal(t, "local-value", ctx.Locals("key"))

		// Test Context
		assert.NotNil(t, ctx.Context())

		// Test Underlying
		assert.Equal(t, c, ctx.Unwrap())

		return ctx.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/test?param=value", nil)
	req.Header.Set("X-Test-Header", "test-value")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "response-value", resp.Header.Get("X-Response-Header"))
}

func TestContext_WithTraceContext(t *testing.T) {
	app := fiber.New()

	app.Use(func(c fiber.Ctx) error {
		// Set trace context in locals (simulating OpenTelemetry middleware)
		c.Locals("trace_context", c.Context())
		return c.Next()
	})

	app.Get("/trace", func(c fiber.Ctx) error {
		ctx := fiberadapter.NewContext(c)
		// Context() should return trace_context from locals when available
		gotCtx := ctx.Context()
		assert.NotNil(t, gotCtx)
		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/trace", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestContextRedirect(t *testing.T) {
	app := fiber.New()

	app.Get("/redirect", func(c fiber.Ctx) error {
		ctx := fiberadapter.NewContext(c)
		return ctx.Redirect("/target", 302)
	})

	req := httptest.NewRequest("GET", "/redirect", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 302, resp.StatusCode)
	assert.Equal(t, "/target", resp.Header.Get("Location"))
}

func TestContextJSON(t *testing.T) {
	app := fiber.New()

	app.Get("/json", func(c fiber.Ctx) error {
		ctx := fiberadapter.NewContext(c)
		return ctx.Status(200).JSON(map[string]string{"key": "value"})
	})

	req := httptest.NewRequest("GET", "/json", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"key":"value"`)
}

func TestContextSendString(t *testing.T) {
	app := fiber.New()

	app.Get("/string", func(c fiber.Ctx) error {
		ctx := fiberadapter.NewContext(c)
		return ctx.Status(200).SendString("Hello World")
	})

	req := httptest.NewRequest("GET", "/string", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "Hello World", string(body))
}

func TestSession(t *testing.T) {
	store := session.NewStore()
	app := fiber.New()

	app.Get("/session", func(c fiber.Ctx) error {
		sess, err := store.Get(c)
		require.NoError(t, err)

		fiberSess := fiberadapter.NewSession(sess)

		// Test Set and Get
		fiberSess.Set("key", "value")
		assert.Equal(t, "value", fiberSess.Get("key"))

		// Test ID
		assert.NotEmpty(t, fiberSess.ID())

		// Test Underlying
		assert.Equal(t, sess, fiberSess.Unwrap())

		// Test Delete
		fiberSess.Delete("key")
		assert.Nil(t, fiberSess.Get("key"))

		// Test Save
		fiberSess.Set("persist", "data")
		err = fiberSess.Save()
		require.NoError(t, err)

		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/session", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestSessionDestroy(t *testing.T) {
	store := session.NewStore()
	app := fiber.New()

	app.Get("/destroy", func(c fiber.Ctx) error {
		sess, err := store.Get(c)
		require.NoError(t, err)

		fiberSess := fiberadapter.NewSession(sess)
		fiberSess.Set("key", "value")

		err = fiberSess.Destroy()
		require.NoError(t, err)

		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/destroy", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestSessionStore(t *testing.T) {
	store := session.NewStore()
	fiberStore := fiberadapter.NewSessionStore(store)

	app := fiber.New()

	app.Get("/store", func(c fiber.Ctx) error {
		ctx := fiberadapter.NewContext(c)

		sess, err := fiberStore.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, sess)

		sess.Set("test", "value")
		assert.Equal(t, "value", sess.Get("test"))

		// Test Underlying
		assert.Equal(t, store, fiberStore.Unwrap())

		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/store", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestSessionStoreInvalidContext(t *testing.T) {
	store := session.NewStore()
	fiberStore := fiberadapter.NewSessionStore(store)

	// A Context not backed by a Fiber request has no fiber.Ctx to key a
	// Fiber session store off.
	_, err := fiberStore.Get(foreignContext{})
	assert.Error(t, err)
	assert.Equal(t, forwardauth.ErrInvalidConfig, err)
}

func TestMiddleware(t *testing.T) {
	store := session.NewStore()

	config := &forwardauth.Config{
		SessionEnabled: true,
		AuthHost:       "auth.example.com",
		LoginPath:      "/_login",
	}
	handler := forwardauth.NewHandler(config)

	app := fiber.New()
	app.Use(fiberadapter.Middleware(handler, store))
	app.Get("/protected", func(c fiber.Ctx) error {
		return c.SendString("Protected content")
	})

	// Test unauthenticated request (should redirect for HTML)
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 302, resp.StatusCode)
}

func TestCheckRoute(t *testing.T) {
	store := session.NewStore()

	config := &forwardauth.Config{
		SessionEnabled: true,
		AuthHost:       "auth.example.com",
	}
	handler := forwardauth.NewHandler(config)

	app := fiber.New()
	app.All("/_auth", fiberadapter.CheckRoute(handler, store))

	// Test unauthenticated request
	req := httptest.NewRequest("GET", "/_auth", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	// Should return redirect or error for unauthenticated
	assert.True(t, resp.StatusCode >= 300)
}

func TestMiddlewareWithPasswordAuth(t *testing.T) {
	store := session.NewStore()

	config := &forwardauth.Config{
		PasswordEnabled: true,
		PasswordHeader:  "X-Auth-Password",
		ValidPasswords:  []string{"SECRET123"},
	}
	handler := forwardauth.NewHandler(config)

	app := fiber.New()
	app.All("/_auth", fiberadapter.Middleware(handler, store))

	// Test with valid password
	req := httptest.NewRequest("GET", "/_auth", nil)
	req.Header.Set("X-Auth-Password", "secret123") // Will be uppercased
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestMiddleware_StepUpRequired(t *testing.T) {
	store := session.NewStore()

	config := &forwardauth.Config{
		SessionEnabled:   true,
		StepUpEnabled:    true,
		StepUpPaths:      []string{"/admin/*"},
		StepUpSessionKey: "step_up_verified",
		AuthHost:         "auth.example.com",
		LoginPath:        "/_login",
		StepUpURL:        "/_step_up",
	}
	handler := forwardauth.NewHandler(config)

	app := fiber.New()
	// Login route without auth - creates session with auth
	app.Get("/login", func(c fiber.Ctx) error {
		sess, err := store.Get(c)
		require.NoError(t, err)
		sess.Set(forwardauth.KeyAuthenticated, true)
		sess.Set(forwardauth.KeyUserID, "user-1")
		require.NoError(t, sess.Save())
		return c.SendString("ok")
	})
	// Protected route with step-up - middleware runs here
	app.Get("/admin/settings", fiberadapter.Middleware(handler, store), func(c fiber.Ctx) error {
		return c.SendString("admin")
	})

	// First get session with auth
	req := httptest.NewRequest("GET", "/login", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	// Use session cookie for step-up path (no step_up_verified in session)
	req = httptest.NewRequest("GET", "/admin/settings", nil)
	req.Header.Set("Accept", "text/html")
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}
	resp, err = app.Test(req)
	require.NoError(t, err)
	// Step-up required -> redirect to step-up URL
	assert.Equal(t, 302, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/_step_up")
}

func TestCookieHelper(t *testing.T) {
	helper := fiberadapter.NewCookieHelper(".example.com", true)

	app := fiber.New()

	app.Get("/set-cookie", func(c fiber.Ctx) error {
		helper.SetCallbackCookie(c, "callback", "https://app.example.com", 600)
		return c.SendStatus(200)
	})

	app.Get("/get-cookie", func(c fiber.Ctx) error {
		value := helper.GetCallbackCookie(c, "callback")
		return c.SendString(value)
	})

	app.Get("/clear-cookie", func(c fiber.Ctx) error {
		helper.ClearCallbackCookie(c, "callback")
		return c.SendStatus(200)
	})

	// Test set cookie
	req := httptest.NewRequest("GET", "/set-cookie", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	cookies := resp.Cookies()
	var callbackCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "callback" {
			callbackCookie = c
			break
		}
	}
	require.NotNil(t, callbackCookie)
	assert.Equal(t, "https://app.example.com", callbackCookie.Value)
	assert.Equal(t, ".example.com", callbackCookie.Domain)
	assert.True(t, callbackCookie.Secure)
	assert.True(t, callbackCookie.HttpOnly)

	// Test GetCallbackCookie - send request with cookie
	req = httptest.NewRequest("GET", "/get-cookie", nil)
	req.AddCookie(callbackCookie)
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "https://app.example.com", string(body))

	// Test GetCallbackCookie - missing cookie returns empty
	req = httptest.NewRequest("GET", "/get-cookie", nil)
	resp, err = app.Test(req)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	assert.Empty(t, string(body))

	// Test clear cookie
	req = httptest.NewRequest("GET", "/clear-cookie", nil)
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestCookieHelperWithoutDomain(t *testing.T) {
	helper := fiberadapter.NewCookieHelper("", false)

	app := fiber.New()

	app.Get("/set-cookie", func(c fiber.Ctx) error {
		helper.SetCallbackCookie(c, "test", "value", 300)
		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/set-cookie", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	cookies := resp.Cookies()
	var testCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "test" {
			testCookie = c
			break
		}
	}
	require.NotNil(t, testCookie)
	assert.Equal(t, "value", testCookie.Value)
	assert.Empty(t, testCookie.Domain)
	assert.False(t, testCookie.Secure)
}

// foreignContext is a forwardauth.Context that is not backed by a Fiber
// request, which is the case SessionStore.Get has to refuse.
type foreignContext struct{}

func (foreignContext) Path() string                              { return "/" }
func (foreignContext) Method() string                            { return "GET" }
func (foreignContext) Protocol() string                          { return "http" }
func (foreignContext) Hostname() string                          { return "example.com" }
func (foreignContext) Get(string) string                         { return "" }
func (foreignContext) Query(string) string                       { return "" }
func (foreignContext) Set(string, string)                        {}
func (foreignContext) SendStatus(int) error                      { return nil }
func (foreignContext) Redirect(string, ...int) error             { return nil }
func (c foreignContext) Status(int) forwardauth.Context          { return c }
func (foreignContext) JSON(interface{}) error                    { return nil }
func (foreignContext) SendString(string) error                   { return nil }
func (foreignContext) Locals(string, ...interface{}) interface{} { return nil }
func (foreignContext) Context() context.Context                  { return context.Background() }

// wrappedContext is what a caller writes when it wants a Context of its own --
// one that decorates the adapter's, or stubs a method for a test -- while
// still being usable with a Fiber session store. It passes the Fiber request
// through, so it satisfies fiberadapter.CtxSource.
type wrappedContext struct {
	foreignContext
	ctx fiber.Ctx
}

func (w wrappedContext) Unwrap() fiber.Ctx { return w.ctx }

// TestSessionStoreAcceptsWrappedContext pins the reason SessionStore.Get asks
// for CtxSource rather than type-asserting to *Context: a caller's own wrapper
// has to keep working. Asserting to the concrete type sent this to
// ErrInvalidConfig.
func TestSessionStoreAcceptsWrappedContext(t *testing.T) {
	store := session.NewStore()
	fiberStore := fiberadapter.NewSessionStore(store)

	app := fiber.New()
	app.Get("/wrapped", func(c fiber.Ctx) error {
		sess, err := fiberStore.Get(wrappedContext{ctx: c})
		require.NoError(t, err)
		require.NotNil(t, sess)
		sess.Set("k", "v")
		assert.Equal(t, "v", sess.Get("k"))
		return c.SendStatus(200)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/wrapped", nil))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

// countingStore is the other half of the same idea: Store is an interface, so
// a store can be wrapped -- here to count lookups, in a real service to add
// metrics or pick a store per tenant.
type countingStore struct {
	inner *session.Store
	calls int
}

func (s *countingStore) Get(c fiber.Ctx) (*session.Session, error) {
	s.calls++
	return s.inner.Get(c)
}

func TestMiddlewareAcceptsWrappedStore(t *testing.T) {
	counting := &countingStore{inner: session.NewStore()}

	handler := forwardauth.NewHandler(&forwardauth.Config{
		SessionEnabled: true,
		AuthHost:       "auth.example.com",
	})

	app := fiber.New()
	app.All("/_auth", fiberadapter.Middleware(handler, counting))

	req := httptest.NewRequest("GET", "/_auth", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, 1, counting.calls)
}

// TestMiddlewareNilStore covers header-only deployments: no session store at
// all, the request judged on its headers. A nil Store must mean "no session",
// not "a session store that panics".
func TestMiddlewareNilStore(t *testing.T) {
	handler := forwardauth.NewHandler(&forwardauth.Config{
		PasswordEnabled: true,
		PasswordHeader:  "X-Auth-Password",
		ValidPasswords:  []string{"SECRET123"},
	})

	app := fiber.New()
	app.All("/_auth", fiberadapter.Middleware(handler, nil))

	req := httptest.NewRequest("GET", "/_auth", nil)
	req.Header.Set("X-Auth-Password", "secret123")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req = httptest.NewRequest("GET", "/_auth", nil)
	req.Header.Set("Accept", "application/json")
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}

// failingStore is the other thing the Store interface buys: a store whose
// lookup fails, which is not something a real *session.Store can be asked to
// do on demand.
type failingStore struct{ err error }

func (s failingStore) Get(fiber.Ctx) (*session.Session, error) { return nil, s.err }

// A store failure is the store's error, passed through unchanged -- the caller
// has to be able to tell a backend outage from a context this adapter cannot
// use, which is ErrInvalidConfig.
func TestSessionStoreGetPassesStoreErrorThrough(t *testing.T) {
	wantErr := errors.New("backend down")
	fiberStore := fiberadapter.NewSessionStore(failingStore{err: wantErr})

	app := fiber.New()
	app.Get("/store", func(c fiber.Ctx) error {
		sess, err := fiberStore.Get(fiberadapter.NewContext(c))
		assert.Nil(t, sess)
		assert.ErrorIs(t, err, wantErr)
		return c.SendStatus(200)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/store", nil))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

// And the endpoint turns that into a 500, not a 401: an outage is not a
// verdict on the user.
func TestMiddlewareStoreFailureIsServerError(t *testing.T) {
	handler := forwardauth.NewHandler(&forwardauth.Config{SessionEnabled: true})

	app := fiber.New()
	app.All("/_auth", fiberadapter.Middleware(handler, failingStore{err: errors.New("backend down")}))

	req := httptest.NewRequest("GET", "/_auth", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)
}
