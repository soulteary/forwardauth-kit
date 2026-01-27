package forwardauth

import (
	"context"

	"github.com/gofiber/fiber/v2"
	fibersession "github.com/gofiber/fiber/v2/middleware/session"
)

// FiberContext wraps a Fiber context to implement the Context interface.
type FiberContext struct {
	ctx *fiber.Ctx
}

// NewFiberContext creates a new FiberContext wrapper.
func NewFiberContext(c *fiber.Ctx) *FiberContext {
	return &FiberContext{ctx: c}
}

// Path returns the request path.
func (c *FiberContext) Path() string {
	return c.ctx.Path()
}

// Method returns the request method.
func (c *FiberContext) Method() string {
	return c.ctx.Method()
}

// Protocol returns the request protocol.
func (c *FiberContext) Protocol() string {
	return c.ctx.Protocol()
}

// Hostname returns the request hostname.
func (c *FiberContext) Hostname() string {
	return c.ctx.Hostname()
}

// Get returns a request header value.
func (c *FiberContext) Get(key string) string {
	return c.ctx.Get(key)
}

// Query returns a query parameter value.
func (c *FiberContext) Query(key string) string {
	return c.ctx.Query(key)
}

// Set sets a response header.
func (c *FiberContext) Set(key, value string) {
	c.ctx.Set(key, value)
}

// SendStatus sends a status code response.
func (c *FiberContext) SendStatus(status int) error {
	return c.ctx.SendStatus(status)
}

// Redirect redirects to the specified location.
func (c *FiberContext) Redirect(location string, status ...int) error {
	if len(status) > 0 {
		return c.ctx.Redirect(location, status[0])
	}
	return c.ctx.Redirect(location)
}

// Status sets the response status code.
func (c *FiberContext) Status(status int) Context {
	c.ctx.Status(status)
	return c
}

// JSON sends a JSON response.
func (c *FiberContext) JSON(v interface{}) error {
	return c.ctx.JSON(v)
}

// SendString sends a string response.
func (c *FiberContext) SendString(s string) error {
	return c.ctx.SendString(s)
}

// Locals gets or sets a local value.
func (c *FiberContext) Locals(key string, value ...interface{}) interface{} {
	if len(value) > 0 {
		c.ctx.Locals(key, value[0])
		return value[0]
	}
	return c.ctx.Locals(key)
}

// Context returns the underlying context.Context.
func (c *FiberContext) Context() context.Context {
	// Get trace context from locals if available
	if traceCtx := c.ctx.Locals("trace_context"); traceCtx != nil {
		if ctx, ok := traceCtx.(context.Context); ok {
			return ctx
		}
	}
	return c.ctx.Context()
}

// Underlying returns the underlying fiber.Ctx.
func (c *FiberContext) Underlying() *fiber.Ctx {
	return c.ctx
}

// FiberSession wraps a Fiber session to implement the Session interface.
type FiberSession struct {
	sess *fibersession.Session
}

// NewFiberSession creates a new FiberSession wrapper.
func NewFiberSession(sess *fibersession.Session) *FiberSession {
	return &FiberSession{sess: sess}
}

// Get returns a session value.
func (s *FiberSession) Get(key string) interface{} {
	return s.sess.Get(key)
}

// Set sets a session value.
func (s *FiberSession) Set(key string, value interface{}) {
	s.sess.Set(key, value)
}

// Delete removes a session value.
func (s *FiberSession) Delete(key string) {
	s.sess.Delete(key)
}

// Save saves the session.
func (s *FiberSession) Save() error {
	return s.sess.Save()
}

// Destroy destroys the session.
func (s *FiberSession) Destroy() error {
	return s.sess.Destroy()
}

// ID returns the session ID.
func (s *FiberSession) ID() string {
	return s.sess.ID()
}

// Underlying returns the underlying fiber session.
func (s *FiberSession) Underlying() *fibersession.Session {
	return s.sess
}

// FiberSessionStore wraps a Fiber session store to implement the SessionStore interface.
type FiberSessionStore struct {
	store *fibersession.Store
}

// NewFiberSessionStore creates a new FiberSessionStore wrapper.
func NewFiberSessionStore(store *fibersession.Store) *FiberSessionStore {
	return &FiberSessionStore{store: store}
}

// Get retrieves the session for the given context.
func (s *FiberSessionStore) Get(c Context) (Session, error) {
	fc, ok := c.(*FiberContext)
	if !ok {
		return nil, ErrInvalidConfig
	}

	sess, err := s.store.Get(fc.ctx)
	if err != nil {
		return nil, err
	}

	return NewFiberSession(sess), nil
}

// Underlying returns the underlying fiber session store.
func (s *FiberSessionStore) Underlying() *fibersession.Store {
	return s.store
}

// FiberMiddleware creates a Fiber middleware for ForwardAuth.
func FiberMiddleware(handler *Handler, store *fibersession.Store) fiber.Handler {
	sessionStore := NewFiberSessionStore(store)

	return func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)

		// Get session
		sess, err := sessionStore.Get(ctx)
		if err != nil {
			return handler.HandleSessionError(ctx, err)
		}

		// Perform authentication check
		result, err := handler.Check(ctx, sess)
		if err != nil {
			switch err {
			case ErrNotAuthenticated, ErrInvalidPassword, ErrUserNotFound:
				return handler.HandleNotAuthenticated(ctx)
			case ErrStepUpRequired:
				return handler.HandleStepUpRequired(ctx)
			case ErrSessionRequired:
				return handler.HandleNotAuthenticated(ctx)
			default:
				return handler.HandleNotAuthenticated(ctx)
			}
		}

		// Set authentication headers
		handler.SetAuthHeaders(ctx, result)

		// Return 200 OK for ForwardAuth
		return c.SendStatus(fiber.StatusOK)
	}
}

// FiberCheckRoute creates a Fiber handler for the ForwardAuth check route.
// This is the main entry point for Traefik/Nginx ForwardAuth integration.
func FiberCheckRoute(handler *Handler, store *fibersession.Store) fiber.Handler {
	return FiberMiddleware(handler, store)
}

// FiberCookieHelper provides cookie utilities for Fiber.
type FiberCookieHelper struct {
	cookieDomain string
	secure       bool
}

// NewFiberCookieHelper creates a new FiberCookieHelper.
func NewFiberCookieHelper(cookieDomain string, secure bool) *FiberCookieHelper {
	return &FiberCookieHelper{
		cookieDomain: cookieDomain,
		secure:       secure,
	}
}

// SetCallbackCookie sets a callback cookie for cross-domain authentication.
func (h *FiberCookieHelper) SetCallbackCookie(c *fiber.Ctx, name, value string, maxAge int) {
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
func (h *FiberCookieHelper) ClearCallbackCookie(c *fiber.Ctx, name string) {
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
func (h *FiberCookieHelper) GetCallbackCookie(c *fiber.Ctx, name string) string {
	return c.Cookies(name)
}
