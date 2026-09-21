// Package fiberadapter serves forwardauth-kit's check endpoint over Fiber v3.
//
// It lives in its own package so that importing the root package does not drag
// Fiber -- and with it fasthttp -- into binaries that never serve a Fiber
// route. A service on net/http, Echo, Gin or chi pays nothing for Fiber
// support existing; only importing this package links it in.
//
// Everything here is a translation layer. Which checks run, what a failed one
// answers, and which headers a successful one emits all live in the root
// package and are reached through [forwardauth.Handler.ServeWithStore]. That
// is deliberate: a second copy of that sequence is a second set of rules about
// when a request counts as authenticated, and the two drift.
//
//	app.All("/_auth", fiberadapter.CheckRoute(handler, store))
package fiberadapter

import (
	"context"

	"github.com/gofiber/fiber/v3"
	fibersession "github.com/gofiber/fiber/v3/middleware/session"

	forwardauth "github.com/soulteary/forwardauth-kit/v3"
)

// Store is the part of a Fiber session store this adapter uses.
//
// *session.Store satisfies it, and so does any wrapper around one -- a store
// chosen per tenant, one that records metrics, a test double. Taking the
// interface rather than the concrete type is what makes those possible without
// a fork of this package.
type Store interface {
	Get(c fiber.Ctx) (*fibersession.Session, error)
}

// CtxSource is the one thing [SessionStore] needs from a
// [forwardauth.Context]: the Fiber request behind it.
//
// [Context] implements it. So can a caller's own wrapper -- one that adds
// logging, or overrides Hostname for a test -- which is the point of asking
// for this rather than type-asserting to *Context: a wrapped context used to
// fail the assertion and come back as [forwardauth.ErrInvalidConfig], with
// nothing saying why.
type CtxSource interface {
	Unwrap() fiber.Ctx
}

// Context wraps a Fiber context to implement [forwardauth.Context].
type Context struct {
	ctx fiber.Ctx
}

// NewContext creates a new Context wrapper.
func NewContext(c fiber.Ctx) *Context {
	return &Context{ctx: c}
}

// Path returns the request path.
func (c *Context) Path() string {
	return c.ctx.Path()
}

// Method returns the request method.
func (c *Context) Method() string {
	return c.ctx.Method()
}

// Protocol returns the request protocol.
func (c *Context) Protocol() string {
	return c.ctx.Scheme()
}

// Hostname returns the request hostname, without the port.
func (c *Context) Hostname() string {
	return c.ctx.Hostname()
}

// Get returns a request header value.
func (c *Context) Get(key string) string {
	return c.ctx.Get(key)
}

// Query returns a query parameter value.
func (c *Context) Query(key string) string {
	return c.ctx.Query(key)
}

// Set sets a response header.
func (c *Context) Set(key, value string) {
	c.ctx.Set(key, value)
}

// SendStatus sends a status code response.
func (c *Context) SendStatus(status int) error {
	return c.ctx.SendStatus(status)
}

// Redirect redirects to the specified location.
func (c *Context) Redirect(location string, status ...int) error {
	if len(status) > 0 {
		return c.ctx.Redirect().Status(status[0]).To(location)
	}
	return c.ctx.Redirect().Status(fiber.StatusFound).To(location)
}

// Status sets the response status code.
func (c *Context) Status(status int) forwardauth.Context {
	c.ctx.Status(status)
	return c
}

// JSON sends a JSON response.
func (c *Context) JSON(v interface{}) error {
	return c.ctx.JSON(v)
}

// SendString sends a string response.
func (c *Context) SendString(s string) error {
	return c.ctx.SendString(s)
}

// Locals gets or sets a local value.
func (c *Context) Locals(key string, value ...interface{}) interface{} {
	if len(value) > 0 {
		c.ctx.Locals(key, value[0])
		return value[0]
	}
	return c.ctx.Locals(key)
}

// Context returns the underlying context.Context.
func (c *Context) Context() context.Context {
	// Get trace context from locals if available
	if traceCtx := c.ctx.Locals("trace_context"); traceCtx != nil {
		if ctx, ok := traceCtx.(context.Context); ok {
			return ctx
		}
	}
	return c.ctx.Context()
}

// Unwrap returns the underlying fiber.Ctx. It implements [CtxSource].
func (c *Context) Unwrap() fiber.Ctx {
	return c.ctx
}

// Session wraps a Fiber session to implement [forwardauth.Session].
//
// The wrapper is not ceremony: a Fiber session keys off interface{} while
// forwardauth.Session keys off string, and this is where the two meet.
type Session struct {
	sess *fibersession.Session
}

// NewSession creates a new Session wrapper.
func NewSession(sess *fibersession.Session) *Session {
	return &Session{sess: sess}
}

// Get returns a session value.
func (s *Session) Get(key string) interface{} {
	return s.sess.Get(key)
}

// Set sets a session value.
func (s *Session) Set(key string, value interface{}) {
	s.sess.Set(key, value)
}

// Delete removes a session value.
func (s *Session) Delete(key string) {
	s.sess.Delete(key)
}

// Save saves the session.
func (s *Session) Save() error {
	return s.sess.Save()
}

// Destroy destroys the session.
func (s *Session) Destroy() error {
	return s.sess.Destroy()
}

// ID returns the session ID.
func (s *Session) ID() string {
	return s.sess.ID()
}

// Unwrap returns the underlying Fiber session.
func (s *Session) Unwrap() *fibersession.Session {
	return s.sess
}

// SessionStore wraps a Fiber session store to implement
// [forwardauth.SessionStore].
type SessionStore struct {
	store Store
}

// NewSessionStore creates a new SessionStore wrapper.
func NewSessionStore(store Store) *SessionStore {
	return &SessionStore{store: store}
}

// Get retrieves the session for the given context.
//
// The context has to be one backed by a Fiber request, because a Fiber session
// store keys off fiber.Ctx; anything else is a configuration error rather than
// a request failure, and comes back as [forwardauth.ErrInvalidConfig].
func (s *SessionStore) Get(c forwardauth.Context) (forwardauth.Session, error) {
	fc, ok := c.(CtxSource)
	if !ok {
		return nil, forwardauth.ErrInvalidConfig
	}

	sess, err := s.store.Get(fc.Unwrap())
	if err != nil {
		return nil, err
	}

	return NewSession(sess), nil
}

// Unwrap returns the underlying Fiber session store.
func (s *SessionStore) Unwrap() Store {
	return s.store
}

// Middleware creates a Fiber handler for the ForwardAuth check endpoint.
//
// store may be nil, in which case the request is checked on its headers alone
// -- see [forwardauth.Handler.ServeWithStore].
func Middleware(handler *forwardauth.Handler, store Store) fiber.Handler {
	var sessionStore forwardauth.SessionStore
	// Not `sessionStore = NewSessionStore(store)` unconditionally: that hands
	// ServeWithStore a non-nil SessionStore holding a nil Store, which fails
	// on the first request instead of meaning "no session".
	if store != nil {
		sessionStore = NewSessionStore(store)
	}

	return func(c fiber.Ctx) error {
		return handler.ServeWithStore(NewContext(c), sessionStore)
	}
}

// CheckRoute creates a Fiber handler for the ForwardAuth check route.
// This is the main entry point for Traefik/Nginx ForwardAuth integration.
func CheckRoute(handler *forwardauth.Handler, store Store) fiber.Handler {
	return Middleware(handler, store)
}

// CookieHelper provides cookie utilities for Fiber.
type CookieHelper struct {
	cookieDomain string
	secure       bool
}

// NewCookieHelper creates a new CookieHelper.
func NewCookieHelper(cookieDomain string, secure bool) *CookieHelper {
	return &CookieHelper{
		cookieDomain: cookieDomain,
		secure:       secure,
	}
}

// SetCallbackCookie sets a callback cookie for cross-domain authentication.
func (h *CookieHelper) SetCallbackCookie(c fiber.Ctx, name, value string, maxAge int) {
	cookie := &fiber.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		SameSite: fiber.CookieSameSiteLaxMode,
		HTTPOnly: true,
		Secure:   h.secure,
	}

	if h.cookieDomain != "" {
		cookie.Domain = h.cookieDomain
	}

	c.Cookie(cookie)
}

// ClearCallbackCookie clears a callback cookie.
func (h *CookieHelper) ClearCallbackCookie(c fiber.Ctx, name string) {
	cookie := &fiber.Cookie{
		Name:     name,
		Value:    "",
		MaxAge:   -1,
		SameSite: fiber.CookieSameSiteLaxMode,
		HTTPOnly: true,
	}

	if h.cookieDomain != "" {
		cookie.Domain = h.cookieDomain
	}

	c.Cookie(cookie)
}

// GetCallbackCookie retrieves a callback cookie value.
func (h *CookieHelper) GetCallbackCookie(c fiber.Ctx, name string) string {
	return c.Cookies(name)
}
