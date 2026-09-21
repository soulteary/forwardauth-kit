// Package httpadapter serves forwardauth-kit's check endpoint over net/http.
//
// It is the counterpart of the fiberadapter subpackage, and it costs nothing
// to import: everything here is standard library, as the root package is.
//
//	mux.Handle("/_auth", httpadapter.CheckRoute(handler, nil))
//
// Everything here is a translation layer. Which checks run, what a failed one
// answers, and which headers a successful one emits all live in the root
// package and are reached through [forwardauth.Handler.ServeWithStore], so
// this adapter and the Fiber one cannot answer the same request differently.
//
// # Sessions
//
// net/http has no session store of its own, so there is nothing here to wrap.
// Pass nil for the store -- the usual shape of a ForwardAuth deployment, where
// sessions live in the authentication service and this endpoint sees only
// headers -- or plug in whatever store the service already uses with
// [forwardauth.SessionStoreFunc].
//
// # Writing an adapter for another framework
//
// Echo, Gin and chi all hand out an http.ResponseWriter and an *http.Request,
// so [NewContext] covers them as it stands. A framework with its own request type
// needs what this file is: an implementation of [forwardauth.Context], and a
// handler that calls [forwardauth.Handler.ServeWithStore] with it. Nothing
// about when a request is authenticated belongs in that code.
package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"

	forwardauth "github.com/soulteary/forwardauth-kit/v3"
)

// Context adapts an http.ResponseWriter and *http.Request pair to
// [forwardauth.Context].
//
// A Context belongs to one request and is not safe for concurrent use, which
// is the same rule net/http's own ResponseWriter carries.
type Context struct {
	w http.ResponseWriter
	r *http.Request

	locals map[string]interface{}

	// status is what Status() recorded, applied by the next method that
	// writes. net/http takes the code at write time, unlike Fiber, where it
	// is a field on the response.
	status int
	// wroteHeader stops a second WriteHeader call. Two of them make net/http
	// log "superfluous response.WriteHeader call" and silently keep the
	// first, so the log line is the only sign anything went wrong.
	wroteHeader bool
}

// NewContext creates a Context for one request.
func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{w: w, r: r, status: http.StatusOK}
}

// Path returns the request path.
func (c *Context) Path() string {
	return c.r.URL.Path
}

// Method returns the request method.
func (c *Context) Method() string {
	return c.r.Method
}

// Protocol returns the scheme this request arrived on: "https" when the
// connection is TLS, "http" otherwise.
//
// It deliberately does not read X-Forwarded-Proto. Whether that header may be
// believed is a property of the deployment, and the decision already lives in
// one place -- [forwardauth.ForwardedHeaders.GetProto] prefers the header and
// falls back to this -- so answering it again here would be a second rule to
// keep in step. Fiber's Scheme() does consult the header, for trusted proxies;
// that is the one place the two adapters differ, and only for a caller reading
// Protocol() directly rather than through ForwardedHeaders.
func (c *Context) Protocol() string {
	if c.r.TLS != nil {
		return "https"
	}
	return "http"
}

// Hostname returns the request host, without the port -- matching what Fiber's
// Hostname() returns, so a Config written against one adapter behaves the same
// on the other.
func (c *Context) Hostname() string {
	return forwardauth.NormalizeHost(c.r.Host)
}

// Get returns a request header value.
func (c *Context) Get(key string) string {
	return c.r.Header.Get(key)
}

// Query returns a query parameter value.
func (c *Context) Query(key string) string {
	return c.r.URL.Query().Get(key)
}

// Set sets a response header. It has no effect once the response header has
// been written, which is net/http's rule, not this adapter's.
func (c *Context) Set(key, value string) {
	c.w.Header().Set(key, value)
}

// SendStatus writes the response header with the given status and no body.
func (c *Context) SendStatus(status int) error {
	c.writeHeader(status)
	return nil
}

// Redirect sends a redirect to location, defaulting to 302 Found.
func (c *Context) Redirect(location string, status ...int) error {
	code := http.StatusFound
	if len(status) > 0 {
		code = status[0]
	}

	c.w.Header().Set("Location", location)
	c.writeHeader(code)
	return nil
}

// Status records the status code for the next write and returns the Context.
func (c *Context) Status(status int) forwardauth.Context {
	c.status = status
	return c
}

// JSON writes v as JSON, with the status recorded by Status.
//
// Content-Type is only set when the caller has not already set one, so a
// caller that chose its own media type keeps it.
func (c *Context) JSON(v interface{}) error {
	if c.w.Header().Get("Content-Type") == "" {
		c.w.Header().Set("Content-Type", "application/json")
	}
	c.writeHeader(c.status)
	return json.NewEncoder(c.w).Encode(v)
}

// SendString writes s as the response body, with the status recorded by
// Status.
func (c *Context) SendString(s string) error {
	c.writeHeader(c.status)
	_, err := c.w.Write([]byte(s))
	return err
}

// Locals gets or sets a request-scoped value.
//
// The values live on the Context, not on the request's context.Context: the
// interface sets as well as gets, and context.Context is immutable, so a Set
// would have had nowhere to go that a later Get could see.
func (c *Context) Locals(key string, value ...interface{}) interface{} {
	if len(value) > 0 {
		if c.locals == nil {
			c.locals = make(map[string]interface{}, 1)
		}
		c.locals[key] = value[0]
		return value[0]
	}
	return c.locals[key]
}

// Context returns the request's context.Context.
func (c *Context) Context() context.Context {
	return c.r.Context()
}

// Request returns the underlying *http.Request.
func (c *Context) Request() *http.Request {
	return c.r
}

// ResponseWriter returns the underlying http.ResponseWriter.
func (c *Context) ResponseWriter() http.ResponseWriter {
	return c.w
}

// writeHeader writes the response header once and remembers that it did.
func (c *Context) writeHeader(status int) {
	if c.wroteHeader {
		return
	}
	c.wroteHeader = true
	c.w.WriteHeader(status)
}

// CheckRoute returns an http.HandlerFunc serving the ForwardAuth check route.
// This is the main entry point for Traefik/Nginx ForwardAuth integration.
//
// store may be nil, in which case the request is checked on its headers alone
// -- see [forwardauth.Handler.ServeWithStore].
//
// There is no Middleware counterpart here, unlike in fiberadapter. In net/http
// a middleware is a func(http.Handler) http.Handler, and this is not one: it
// is the endpoint a proxy calls, and it answers the request itself.
func CheckRoute(handler *forwardauth.Handler, store forwardauth.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The error is the one a write returned; there is no response left to
		// report it in, and the Handler's own logger has already recorded
		// whatever led here.
		_ = handler.ServeWithStore(NewContext(w, r), store)
	}
}
