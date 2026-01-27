package forwardauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthHeaderBuilder_BuildHeaders(t *testing.T) {
	config := &Config{
		UserHeaderName:   "X-Forwarded-User",
		AuthUserHeader:   "X-Auth-User",
		AuthEmailHeader:  "X-Auth-Email",
		AuthScopesHeader: "X-Auth-Scopes",
		AuthRoleHeader:   "X-Auth-Role",
		AuthAMRHeader:    "X-Auth-AMR",
	}
	builder := NewAuthHeaderBuilder(config)

	tests := []struct {
		name   string
		result *AuthResult
		want   map[string]string
	}{
		{
			name:   "nil result",
			result: nil,
			want:   map[string]string{},
		},
		{
			name: "not authenticated",
			result: &AuthResult{
				Authenticated: false,
			},
			want: map[string]string{},
		},
		{
			name: "authenticated without user ID",
			result: &AuthResult{
				Authenticated: true,
			},
			want: map[string]string{
				"X-Forwarded-User": "authenticated",
			},
		},
		{
			name: "authenticated with user ID",
			result: &AuthResult{
				Authenticated: true,
				UserID:        "user-123",
			},
			want: map[string]string{
				"X-Forwarded-User": "user-123",
				"X-Auth-User":      "user-123",
			},
		},
		{
			name: "full user info",
			result: &AuthResult{
				Authenticated: true,
				UserID:        "user-123",
				Email:         "user@example.com",
				Scopes:        []string{"read", "write"},
				Role:          "admin",
				AMR:           []string{"otp", "mfa"},
			},
			want: map[string]string{
				"X-Forwarded-User": "user-123",
				"X-Auth-User":      "user-123",
				"X-Auth-Email":     "user@example.com",
				"X-Auth-Scopes":    "read,write",
				"X-Auth-Role":      "admin",
				"X-Auth-AMR":       "otp,mfa",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := builder.BuildHeaders(tt.result)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthHeaderBuilder_SetHeaders(t *testing.T) {
	config := &Config{
		UserHeaderName:   "X-Forwarded-User",
		AuthUserHeader:   "X-Auth-User",
		AuthEmailHeader:  "X-Auth-Email",
		AuthScopesHeader: "X-Auth-Scopes",
		AuthRoleHeader:   "X-Auth-Role",
		AuthAMRHeader:    "X-Auth-AMR",
	}
	builder := NewAuthHeaderBuilder(config)

	ctx := newMockContext()
	result := &AuthResult{
		Authenticated: true,
		UserID:        "user-123",
		Email:         "user@example.com",
		Scopes:        []string{"read", "write"},
		Role:          "admin",
	}

	builder.SetHeaders(ctx, result)

	assert.Equal(t, "user-123", ctx.respHdrs["X-Forwarded-User"])
	assert.Equal(t, "user-123", ctx.respHdrs["X-Auth-User"])
	assert.Equal(t, "user@example.com", ctx.respHdrs["X-Auth-Email"])
	assert.Equal(t, "read,write", ctx.respHdrs["X-Auth-Scopes"])
	assert.Equal(t, "admin", ctx.respHdrs["X-Auth-Role"])
}

func TestForwardedHeaders_GetHost(t *testing.T) {
	fh := ForwardedHeaders{}

	tests := []struct {
		name          string
		forwardedHost string
		hostname      string
		want          string
	}{
		{
			name:     "no forwarded host",
			hostname: "example.com",
			want:     "example.com",
		},
		{
			name:          "with forwarded host",
			forwardedHost: "forwarded.example.com",
			hostname:      "example.com",
			want:          "forwarded.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.hostname = tt.hostname
			if tt.forwardedHost != "" {
				ctx.headers["X-Forwarded-Host"] = tt.forwardedHost
			}

			got := fh.GetHost(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestForwardedHeaders_GetURI(t *testing.T) {
	fh := ForwardedHeaders{}

	tests := []struct {
		name         string
		forwardedURI string
		path         string
		want         string
	}{
		{
			name: "no forwarded URI",
			path: "/api/users",
			want: "/api/users",
		},
		{
			name:         "with forwarded URI",
			forwardedURI: "/original/path",
			path:         "/api/users",
			want:         "/original/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.path = tt.path
			if tt.forwardedURI != "" {
				ctx.headers["X-Forwarded-Uri"] = tt.forwardedURI
			}

			got := fh.GetURI(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestForwardedHeaders_GetProto(t *testing.T) {
	fh := ForwardedHeaders{}

	tests := []struct {
		name           string
		forwardedProto string
		protocol       string
		want           string
	}{
		{
			name:     "no forwarded proto",
			protocol: "https",
			want:     "https",
		},
		{
			name:           "with forwarded proto",
			forwardedProto: "http",
			protocol:       "https",
			want:           "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.protocol = tt.protocol
			if tt.forwardedProto != "" {
				ctx.headers["X-Forwarded-Proto"] = tt.forwardedProto
			}

			got := fh.GetProto(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestForwardedHeaders_GetMethod(t *testing.T) {
	fh := ForwardedHeaders{}

	tests := []struct {
		name            string
		forwardedMethod string
		method          string
		want            string
	}{
		{
			name:   "no forwarded method",
			method: "GET",
			want:   "GET",
		},
		{
			name:            "with forwarded method",
			forwardedMethod: "POST",
			method:          "GET",
			want:            "POST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.method = tt.method
			if tt.forwardedMethod != "" {
				ctx.headers["X-Forwarded-Method"] = tt.forwardedMethod
			}

			got := fh.GetMethod(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestForwardedHeaders_BuildCallbackURL(t *testing.T) {
	fh := ForwardedHeaders{}

	ctx := newMockContext()
	ctx.hostname = "app.example.com"
	ctx.protocol = "https"

	url := fh.BuildCallbackURL(ctx, "auth.example.com", "/_login", "callback")
	assert.Equal(t, "https://auth.example.com/_login?callback=app.example.com", url)
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "host without port",
			host: "example.com",
			want: "example.com",
		},
		{
			name: "host with port",
			host: "example.com:8080",
			want: "example.com",
		},
		{
			name: "IPv4 with port",
			host: "192.168.1.1:8080",
			want: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeHost(tt.host)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestForwardedHeaders_IsDifferentDomain(t *testing.T) {
	fh := ForwardedHeaders{}

	tests := []struct {
		name     string
		origin   string
		authHost string
		want     bool
	}{
		{
			name:     "same domain",
			origin:   "example.com",
			authHost: "example.com",
			want:     false,
		},
		{
			name:     "different domain",
			origin:   "app.example.com",
			authHost: "auth.example.com",
			want:     true,
		},
		{
			name:     "same domain with port",
			origin:   "example.com:8080",
			authHost: "example.com",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.hostname = tt.origin

			got := fh.IsDifferentDomain(ctx, tt.authHost)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestForwardedHeaders_GetForwardedFor(t *testing.T) {
	fh := ForwardedHeaders{}

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "no header",
			header: "",
			want:   "",
		},
		{
			name:   "single IP",
			header: "192.168.1.1",
			want:   "192.168.1.1",
		},
		{
			name:   "multiple IPs",
			header: "192.168.1.1, 10.0.0.1, 172.16.0.1",
			want:   "192.168.1.1, 10.0.0.1, 172.16.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			if tt.header != "" {
				ctx.headers["X-Forwarded-For"] = tt.header
			}

			got := fh.GetForwardedFor(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestForwardedHeaders_GetRealIP(t *testing.T) {
	fh := ForwardedHeaders{}

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "no header",
			header: "",
			want:   "",
		},
		{
			name:   "with IP",
			header: "192.168.1.100",
			want:   "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			if tt.header != "" {
				ctx.headers["X-Real-IP"] = tt.header
			}

			got := fh.GetRealIP(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthHeaderBuilder_EmptyScopes(t *testing.T) {
	config := &Config{
		UserHeaderName:   "X-Forwarded-User",
		AuthUserHeader:   "X-Auth-User",
		AuthEmailHeader:  "X-Auth-Email",
		AuthScopesHeader: "X-Auth-Scopes",
		AuthRoleHeader:   "X-Auth-Role",
		AuthAMRHeader:    "X-Auth-AMR",
	}
	builder := NewAuthHeaderBuilder(config)

	result := &AuthResult{
		Authenticated: true,
		UserID:        "user-123",
		Scopes:        []string{}, // Empty scopes
		AMR:           []string{}, // Empty AMR
	}

	headers := builder.BuildHeaders(result)

	assert.Equal(t, "user-123", headers["X-Forwarded-User"])
	assert.Equal(t, "user-123", headers["X-Auth-User"])
	// Empty slices should not set headers
	_, hasScopes := headers["X-Auth-Scopes"]
	_, hasAMR := headers["X-Auth-AMR"]
	assert.False(t, hasScopes)
	assert.False(t, hasAMR)
}

func TestForwardedHeaders_BuildCallbackURL_WithForwardedHeaders(t *testing.T) {
	fh := ForwardedHeaders{}

	ctx := newMockContext()
	ctx.headers["X-Forwarded-Host"] = "forwarded.example.com"
	ctx.headers["X-Forwarded-Proto"] = "http"

	url := fh.BuildCallbackURL(ctx, "auth.example.com", "/_login", "callback")
	assert.Equal(t, "http://auth.example.com/_login?callback=forwarded.example.com", url)
}
