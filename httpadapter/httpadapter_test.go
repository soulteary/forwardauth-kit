package httpadapter_test

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	forwardauth "github.com/soulteary/forwardauth-kit/v3"
	"github.com/soulteary/forwardauth-kit/v3/httpadapter"
)

func TestContextRequestAccessors(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/check?param=value", nil)
	req.Header.Set("X-Test-Header", "test-value")
	rec := httptest.NewRecorder()

	c := httpadapter.NewContext(rec, req)

	assert.Equal(t, "/check", c.Path())
	assert.Equal(t, http.MethodPost, c.Method())
	assert.Equal(t, "http", c.Protocol())
	assert.Equal(t, "example.com", c.Hostname())
	assert.Equal(t, "test-value", c.Get("X-Test-Header"))
	assert.Equal(t, "", c.Get("X-Missing-Header"))
	assert.Equal(t, "value", c.Query("param"))
	assert.Equal(t, "", c.Query("missing"))
	assert.Equal(t, req.Context(), c.Context())
	assert.Same(t, req, c.Request())
	assert.Equal(t, rec, c.ResponseWriter())
}

func TestContextProtocolTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.TLS = &tls.ConnectionState{}

	assert.Equal(t, "https", httpadapter.NewContext(httptest.NewRecorder(), req).Protocol())
}

// Hostname drops the port, as Fiber's does. A Config comparing AuthHost
// against the request host has to see the same value from either adapter.
func TestContextHostnameStripsPort(t *testing.T) {
	for host, want := range map[string]string{
		"example.com":      "example.com",
		"example.com:8080": "example.com",
		"[::1]:8080":       "::1",
	} {
		req := httptest.NewRequest(http.MethodGet, "/check", nil)
		req.Host = host
		assert.Equal(t, want, httpadapter.NewContext(httptest.NewRecorder(), req).Hostname(), host)
	}
}

func TestContextSetHeaderAndSendStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	c := httpadapter.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check", nil))

	c.Set("X-Response-Header", "response-value")
	require.NoError(t, c.SendStatus(http.StatusNoContent))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "response-value", rec.Header().Get("X-Response-Header"))
	assert.Empty(t, rec.Body.String())
}

func TestContextRedirect(t *testing.T) {
	t.Run("default status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c := httpadapter.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check", nil))

		require.NoError(t, c.Redirect("/target"))

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/target", rec.Header().Get("Location"))
	})

	t.Run("explicit status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c := httpadapter.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check", nil))

		require.NoError(t, c.Redirect("/target", http.StatusSeeOther))

		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "/target", rec.Header().Get("Location"))
	})
}

func TestContextStatusJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	c := httpadapter.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check", nil))

	require.NoError(t, c.Status(http.StatusTeapot).JSON(map[string]string{"key": "value"}))

	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]string{"key": "value"}, body)
}

// JSON must not overwrite a Content-Type the caller chose. SendErrorResponse
// sets one before calling it, and a caller may set a more specific one.
func TestContextJSONKeepsCallerContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	c := httpadapter.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check", nil))

	c.Set("Content-Type", "application/problem+json")
	require.NoError(t, c.JSON(map[string]string{"key": "value"}))

	assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
}

func TestContextStatusSendString(t *testing.T) {
	rec := httptest.NewRecorder()
	c := httpadapter.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check", nil))

	require.NoError(t, c.Status(http.StatusForbidden).SendString("Hello World"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "Hello World", rec.Body.String())
}

// Without Status the body goes out as 200, which is what Fiber does too.
func TestContextSendStringDefaultsTo200(t *testing.T) {
	rec := httptest.NewRecorder()
	c := httpadapter.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check", nil))

	require.NoError(t, c.SendString("ok"))

	assert.Equal(t, http.StatusOK, rec.Code)
}

// A second write must not call WriteHeader again: net/http would keep the
// first code and log "superfluous response.WriteHeader call", leaving the log
// line as the only sign of it.
func TestContextWritesHeaderOnce(t *testing.T) {
	rec := httptest.NewRecorder()
	c := httpadapter.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check", nil))

	require.NoError(t, c.Status(http.StatusUnauthorized).SendString("first"))
	require.NoError(t, c.Status(http.StatusInternalServerError).SendString("second"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "firstsecond", rec.Body.String())
}

func TestContextLocals(t *testing.T) {
	c := httpadapter.NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/check", nil))

	assert.Nil(t, c.Locals("missing"))
	assert.Equal(t, "local-value", c.Locals("key", "local-value"))
	assert.Equal(t, "local-value", c.Locals("key"))
}

// Context satisfies the interface the root package is written against.
var _ forwardauth.Context = (*httpadapter.Context)(nil)

func newSessionHandler() *forwardauth.Handler {
	return forwardauth.NewHandler(&forwardauth.Config{
		SessionEnabled: true,
		AuthHost:       "auth.example.com",
		LoginPath:      "/_login",
	})
}

func TestCheckRouteUnauthenticatedJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	req.Header.Set("Accept", "application/json")

	httpadapter.CheckRoute(newSessionHandler(), nil)(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "authentication required")
}

func TestCheckRouteUnauthenticatedHTMLRedirects(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")

	httpadapter.CheckRoute(newSessionHandler(), nil)(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t,
		"https://auth.example.com/_login?callback=app.example.com",
		rec.Header().Get("Location"))
}

func TestCheckRouteWithPasswordAuth(t *testing.T) {
	handler := forwardauth.NewHandler(&forwardauth.Config{
		PasswordEnabled: true,
		PasswordHeader:  "X-Auth-Password",
		ValidPasswords:  []string{"SECRET123"},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	req.Header.Set("X-Auth-Password", "secret123") // the default normalizer upper-cases

	httpadapter.CheckRoute(handler, nil)(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "authenticated", rec.Header().Get("X-Forwarded-User"))
}

// The authentication headers a proxy forwards downstream are built by the root
// package; the adapter only has to let them reach the response.
func TestCheckRouteEmitsAuthHeaders(t *testing.T) {
	handler := forwardauth.NewHandler(&forwardauth.Config{SessionEnabled: true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)

	httpadapter.CheckRoute(handler, sessionWith(map[string]interface{}{
		forwardauth.KeyAuthenticated: true,
		forwardauth.KeyUserID:        "user-1",
		forwardauth.KeyUserMail:      "user@example.com",
		forwardauth.KeyUserScope:     []string{"read", "write"},
		forwardauth.KeyUserRole:      "admin",
	}))(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user-1", rec.Header().Get("X-Forwarded-User"))
	assert.Equal(t, "user-1", rec.Header().Get("X-Auth-User"))
	assert.Equal(t, "user@example.com", rec.Header().Get("X-Auth-Email"))
	assert.Equal(t, "read,write", rec.Header().Get("X-Auth-Scopes"))
	assert.Equal(t, "admin", rec.Header().Get("X-Auth-Role"))
}

func TestCheckRouteStepUpRequired(t *testing.T) {
	handler := forwardauth.NewHandler(&forwardauth.Config{
		SessionEnabled:            true,
		StepUpEnabled:             true,
		StepUpPaths:               []string{"/admin/*"},
		StepUpForwardedURITrusted: true,
		AuthHost:                  "auth.example.com",
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-Uri", "/admin/settings")

	httpadapter.CheckRoute(handler, sessionWith(map[string]interface{}{
		forwardauth.KeyAuthenticated: true,
		forwardauth.KeyUserID:        "user-1",
	}))(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/_step_up")
}

func TestCheckRouteSessionStoreError(t *testing.T) {
	failing := forwardauth.SessionStoreFunc(func(forwardauth.Context) (forwardauth.Session, error) {
		return nil, errors.New("backend down")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	req.Header.Set("Accept", "application/json")

	httpadapter.CheckRoute(newSessionHandler(), failing)(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "session store error")
}

// A nil store means no session, not a nil-pointer panic: the header-only
// deployment, where sessions live in the authentication service.
func TestCheckRouteNilStore(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	req.Header.Set("Accept", "application/json")

	assert.NotPanics(t, func() {
		httpadapter.CheckRoute(newSessionHandler(), nil)(rec, req)
	})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// sessionWith is the whole of what SessionStoreFunc asks of a caller: hand
// back something satisfying forwardauth.Session.
func sessionWith(data map[string]interface{}) forwardauth.SessionStore {
	return forwardauth.SessionStoreFunc(func(forwardauth.Context) (forwardauth.Session, error) {
		return &mapSession{data: data}, nil
	})
}

type mapSession struct {
	data map[string]interface{}
}

func (s *mapSession) Get(key string) interface{}    { return s.data[key] }
func (s *mapSession) Set(key string, v interface{}) { s.data[key] = v }
func (s *mapSession) Delete(key string)             { delete(s.data, key) }
func (s *mapSession) Save() error                   { return nil }
func (s *mapSession) Destroy() error                { clear(s.data); return nil }
func (s *mapSession) ID() string                    { return "test-session" }
