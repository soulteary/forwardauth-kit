package forwardauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFiberContext(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)

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
		assert.Equal(t, c, ctx.Underlying())

		return ctx.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/test?param=value", nil)
	req.Header.Set("X-Test-Header", "test-value")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "response-value", resp.Header.Get("X-Response-Header"))
}

func TestFiberContext_WithTraceContext(t *testing.T) {
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		// Set trace context in locals (simulating OpenTelemetry middleware)
		c.Locals("trace_context", c.Context())
		return c.Next()
	})

	app.Get("/trace", func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)
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

func TestFiberContextRedirect(t *testing.T) {
	app := fiber.New()

	app.Get("/redirect", func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)
		return ctx.Redirect("/target", 302)
	})

	req := httptest.NewRequest("GET", "/redirect", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 302, resp.StatusCode)
	assert.Equal(t, "/target", resp.Header.Get("Location"))
}

func TestFiberContextJSON(t *testing.T) {
	app := fiber.New()

	app.Get("/json", func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)
		return ctx.Status(200).JSON(map[string]string{"key": "value"})
	})

	req := httptest.NewRequest("GET", "/json", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"key":"value"`)
}

func TestFiberContextSendString(t *testing.T) {
	app := fiber.New()

	app.Get("/string", func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)
		return ctx.Status(200).SendString("Hello World")
	})

	req := httptest.NewRequest("GET", "/string", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "Hello World", string(body))
}

func TestFiberSession(t *testing.T) {
	store := session.New()
	app := fiber.New()

	app.Get("/session", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		require.NoError(t, err)

		fiberSess := NewFiberSession(sess)

		// Test Set and Get
		fiberSess.Set("key", "value")
		assert.Equal(t, "value", fiberSess.Get("key"))

		// Test ID
		assert.NotEmpty(t, fiberSess.ID())

		// Test Underlying
		assert.Equal(t, sess, fiberSess.Underlying())

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

func TestFiberSessionDestroy(t *testing.T) {
	store := session.New()
	app := fiber.New()

	app.Get("/destroy", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		require.NoError(t, err)

		fiberSess := NewFiberSession(sess)
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

func TestFiberSessionStore(t *testing.T) {
	store := session.New()
	fiberStore := NewFiberSessionStore(store)

	app := fiber.New()

	app.Get("/store", func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)

		sess, err := fiberStore.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, sess)

		sess.Set("test", "value")
		assert.Equal(t, "value", sess.Get("test"))

		// Test Underlying
		assert.Equal(t, store, fiberStore.Underlying())

		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/store", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestFiberSessionStoreInvalidContext(t *testing.T) {
	store := session.New()
	fiberStore := NewFiberSessionStore(store)

	// Use mock context instead of FiberContext
	mockCtx := newMockContext()
	_, err := fiberStore.Get(mockCtx)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidConfig, err)
}

func TestFiberMiddleware(t *testing.T) {
	store := session.New()

	config := &Config{
		SessionEnabled: true,
		AuthHost:       "auth.example.com",
		LoginPath:      "/_login",
	}
	handler := NewHandler(config)

	app := fiber.New()
	app.Use(FiberMiddleware(handler, store))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("Protected content")
	})

	// Test unauthenticated request (should redirect for HTML)
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 302, resp.StatusCode)
}

func TestFiberCheckRoute(t *testing.T) {
	store := session.New()

	config := &Config{
		SessionEnabled: true,
		AuthHost:       "auth.example.com",
	}
	handler := NewHandler(config)

	app := fiber.New()
	app.All("/_auth", FiberCheckRoute(handler, store))

	// Test unauthenticated request
	req := httptest.NewRequest("GET", "/_auth", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	// Should return redirect or error for unauthenticated
	assert.True(t, resp.StatusCode >= 300)
}

func TestFiberMiddlewareWithPasswordAuth(t *testing.T) {
	store := session.New()

	config := &Config{
		PasswordEnabled: true,
		PasswordHeader:  "X-Auth-Password",
		ValidPasswords:  []string{"SECRET123"},
	}
	handler := NewHandler(config)

	app := fiber.New()
	app.All("/_auth", FiberMiddleware(handler, store))

	// Test with valid password
	req := httptest.NewRequest("GET", "/_auth", nil)
	req.Header.Set("X-Auth-Password", "secret123") // Will be uppercased
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestFiberMiddleware_StepUpRequired(t *testing.T) {
	store := session.New()

	config := &Config{
		SessionEnabled:   true,
		StepUpEnabled:    true,
		StepUpPaths:      []string{"/admin/*"},
		StepUpSessionKey: "step_up_verified",
		AuthHost:         "auth.example.com",
		LoginPath:        "/_login",
		StepUpURL:        "/_step_up",
	}
	handler := NewHandler(config)

	app := fiber.New()
	// Login route without auth - creates session with auth
	app.Get("/login", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		require.NoError(t, err)
		sess.Set(KeyAuthenticated, true)
		sess.Set(KeyUserID, "user-1")
		require.NoError(t, sess.Save())
		return c.SendString("ok")
	})
	// Protected route with step-up - middleware runs here
	app.Get("/admin/settings", FiberMiddleware(handler, store), func(c *fiber.Ctx) error {
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

func TestFiberCookieHelper(t *testing.T) {
	helper := NewFiberCookieHelper(".example.com", true)

	app := fiber.New()

	app.Get("/set-cookie", func(c *fiber.Ctx) error {
		helper.SetCallbackCookie(c, "callback", "https://app.example.com", 600)
		return c.SendStatus(200)
	})

	app.Get("/get-cookie", func(c *fiber.Ctx) error {
		value := helper.GetCallbackCookie(c, "callback")
		return c.SendString(value)
	})

	app.Get("/clear-cookie", func(c *fiber.Ctx) error {
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

func TestFiberCookieHelperWithoutDomain(t *testing.T) {
	helper := NewFiberCookieHelper("", false)

	app := fiber.New()

	app.Get("/set-cookie", func(c *fiber.Ctx) error {
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
