package forwardauth

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

// AuthHeaderBuilder builds authentication headers for downstream services.
type AuthHeaderBuilder struct {
	config *Config
}

// NewAuthHeaderBuilder creates a new AuthHeaderBuilder.
func NewAuthHeaderBuilder(config *Config) *AuthHeaderBuilder {
	return &AuthHeaderBuilder{config: config}
}

// BuildHeaders builds the authentication headers from an AuthResult.
func (b *AuthHeaderBuilder) BuildHeaders(result *AuthResult) map[string]string {
	headers := make(map[string]string)

	if result == nil || !result.Authenticated {
		return headers
	}

	// Set primary user header.
	//
	// An unrepresentable user id is treated as no id at all, which is what the
	// existing empty-id branch already does: the request is still known to be
	// authenticated, but nothing downstream is told WHO by a value this
	// package cannot vouch for.
	if id, ok := safeHeaderValue(result.UserID); ok && id != "" {
		headers[b.config.UserHeaderName] = id
		headers[b.config.AuthUserHeader] = id
	} else {
		headers[b.config.UserHeaderName] = "authenticated"
	}

	// Set email header
	if email, ok := safeHeaderValue(result.Email); ok && email != "" {
		headers[b.config.AuthEmailHeader] = email
	}

	// Set name header
	if name, ok := safeHeaderValue(result.Name); ok && name != "" && b.config.AuthNameHeader != "" {
		headers[b.config.AuthNameHeader] = name
	}

	// Set scopes header (comma-separated).
	//
	// A scope containing the separator would be split into two by any
	// downstream parser (ParseScopesFromHeader included), so a value carrying
	// a comma could mint extra permissions. Such values are dropped rather
	// than passed on.
	if scopes := sanitizeList(result.Scopes); len(scopes) > 0 {
		headers[b.config.AuthScopesHeader] = strings.Join(scopes, ",")
	}

	// Set role header
	if role, ok := safeHeaderValue(result.Role); ok && role != "" {
		headers[b.config.AuthRoleHeader] = role
	}

	// Set AMR header (comma-separated)
	if amr := sanitizeList(result.AMR); len(amr) > 0 {
		headers[b.config.AuthAMRHeader] = strings.Join(amr, ",")
	}

	return headers
}

// unsafeHeaderChars cannot appear in a header value: CR and LF would end the
// field and begin another, and NUL terminates or is rejected outright
// depending on what reads the header next.
const unsafeHeaderChars = "\r\n\x00"

// sanitizeList drops entries that cannot be represented safely in a
// comma-separated header value: ones containing the separator, or characters
// that would let a value break out of the header.
func sanitizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.ContainsAny(v, ","+unsafeHeaderChars) || strings.TrimSpace(v) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(v))
	}
	return out
}

// safeHeaderValue returns v and whether it can be emitted as a header value.
//
// An unsafe value is DROPPED, not repaired. Deleting the offending characters
// joins what surrounded them into a different, well-formed value the caller
// never held: a role of "ad\r\nmin" came out as "X-Auth-Role: admin", turning
// a malformed directory entry into the exact privileged token a downstream
// service authorizes -- so the repair was strictly worse than emitting
// nothing. sanitizeList has always dropped such entries; this is the scalar
// half of the same rule.
func safeHeaderValue(v string) (string, bool) {
	if strings.ContainsAny(v, unsafeHeaderChars) {
		return "", false
	}
	return v, true
}

// SetHeaders sets the authentication headers on the context.
func (b *AuthHeaderBuilder) SetHeaders(c Context, result *AuthResult) {
	headers := b.BuildHeaders(result)
	for key, value := range headers {
		c.Set(key, value)
	}
}

// ForwardedHeaders provides utilities for working with X-Forwarded-* headers.
type ForwardedHeaders struct{}

// GetHost returns the forwarded hostname from the request.
// It prioritizes the X-Forwarded-Host header if present.
func (ForwardedHeaders) GetHost(c Context) string {
	forwardedHost := c.Get("X-Forwarded-Host")
	if forwardedHost != "" {
		return forwardedHost
	}
	return c.Hostname()
}

// GetURI returns the forwarded URI from the request.
// It prioritizes the X-Forwarded-Uri header if present.
func (ForwardedHeaders) GetURI(c Context) string {
	forwardedURI := c.Get("X-Forwarded-Uri")
	if forwardedURI != "" {
		return forwardedURI
	}
	return c.Path()
}

// forwardedPath returns just the path component of a forwarded URI.
//
// X-Forwarded-Uri commonly carries the query string -- the README's own nginx
// configuration passes $request_uri, which does. A path matcher anchored at
// both ends therefore failed to match "/settings/security?tab=password"
// against "/settings/security", so a protected route silently skipped its
// check whenever a query parameter was present.
func forwardedPath(uri string) string {
	if uri == "" {
		return uri
	}
	// Strip the fragment first: a query may follow it in a malformed value,
	// and neither belongs to the path.
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i]
	}
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	return uri
}

// canonicalForwardedPath returns forwardedPath's result with percent-escapes
// decoded and "." / ".." segments collapsed -- the spelling a downstream
// router actually routes on.
//
// "/%61dmin/settings" is not "/admin/settings" to a matcher comparing bytes,
// but net/http's ServeMux routes on the decoded URL.Path and sends it to the
// /admin handler, so a step-up pattern of "/admin/*" was walked straight past.
//
// stepUpRequiredFor matches BOTH this and the raw spelling, so decoding can
// only ever add matches, never silence one that used to fire. An escape
// sequence this cannot decode is left alone for the same reason.
func canonicalForwardedPath(uri string) string {
	p := forwardedPath(uri)
	if p == "" {
		return p
	}
	if decoded, err := url.PathUnescape(p); err == nil {
		p = decoded
	}
	cleaned := path.Clean(p)
	// path.Clean drops a trailing slash, which a pattern may distinguish.
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

// GetProto returns the forwarded protocol from the request.
// It prioritizes the X-Forwarded-Proto header if present.
func (ForwardedHeaders) GetProto(c Context) string {
	forwardedProto := c.Get("X-Forwarded-Proto")
	if forwardedProto != "" {
		return forwardedProto
	}
	return c.Protocol()
}

// GetMethod returns the forwarded method from the request.
// It prioritizes the X-Forwarded-Method header if present.
func (h ForwardedHeaders) GetMethod(c Context) string {
	forwardedMethod := c.Get("X-Forwarded-Method")
	if forwardedMethod != "" {
		return forwardedMethod
	}
	return c.Method()
}

// GetForwardedFor returns the X-Forwarded-For header value.
func (ForwardedHeaders) GetForwardedFor(c Context) string {
	return c.Get("X-Forwarded-For")
}

// GetRealIP returns the X-Real-IP header value.
func (ForwardedHeaders) GetRealIP(c Context) string {
	return c.Get("X-Real-IP")
}

// BuildCallbackURL constructs a callback URL for authentication redirects.
func (h ForwardedHeaders) BuildCallbackURL(c Context, authHost, loginPath, callbackParam string) string {
	callbackHost := h.GetHost(c)
	proto := h.GetProto(c)

	return fmt.Sprintf("%s://%s%s?%s=%s", proto, authHost, loginPath, callbackParam, callbackHost)
}

// NormalizeHost removes the port from a host for comparison.
//
// net.SplitHostPort handles bracketed IPv6 literals; the previous
// strings.Index(host, ":") truncated "[::1]:8080" to "[".
func NormalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	// No port: strip brackets from a bare IPv6 literal so it compares equal to
	// the same address with a port.
	return strings.Trim(host, "[]")
}

// IsDifferentDomain checks if the origin host is different from the auth host.
func (h ForwardedHeaders) IsDifferentDomain(c Context, authHost string) bool {
	originHost := NormalizeHost(h.GetHost(c))
	normalizedAuthHost := NormalizeHost(authHost)
	return originHost != normalizedAuthHost
}
