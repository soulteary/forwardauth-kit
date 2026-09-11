package forwardauth

import (
	"fmt"
	"net"
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

	// Set primary user header
	if result.UserID != "" {
		headers[b.config.UserHeaderName] = sanitizeHeaderValue(result.UserID)
		headers[b.config.AuthUserHeader] = sanitizeHeaderValue(result.UserID)
	} else {
		headers[b.config.UserHeaderName] = "authenticated"
	}

	// Set email header
	if result.Email != "" {
		headers[b.config.AuthEmailHeader] = sanitizeHeaderValue(result.Email)
	}

	// Set name header
	if result.Name != "" && b.config.AuthNameHeader != "" {
		headers[b.config.AuthNameHeader] = sanitizeHeaderValue(result.Name)
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
	if result.Role != "" {
		headers[b.config.AuthRoleHeader] = sanitizeHeaderValue(result.Role)
	}

	// Set AMR header (comma-separated)
	if amr := sanitizeList(result.AMR); len(amr) > 0 {
		headers[b.config.AuthAMRHeader] = strings.Join(amr, ",")
	}

	return headers
}

// sanitizeList drops entries that cannot be represented safely in a
// comma-separated header value: ones containing the separator, or control
// characters that would let a value break out of the header.
func sanitizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.ContainsAny(v, ",\r\n") || strings.TrimSpace(v) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(v))
	}
	return out
}

// sanitizeHeaderValue strips characters that would let a value break out of a
// single header field.
func sanitizeHeaderValue(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, v)
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
