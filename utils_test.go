package forwardauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsHTMLRequest(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{
			name:   "empty accept header",
			accept: "",
			want:   true,
		},
		{
			name:   "text/html",
			accept: "text/html",
			want:   true,
		},
		{
			name:   "text/html with quality",
			accept: "text/html,application/xhtml+xml,application/xml;q=0.9",
			want:   true,
		},
		{
			name:   "*/* first",
			accept: "*/*",
			want:   true,
		},
		{
			name:   "application/json",
			accept: "application/json",
			want:   false,
		},
		{
			name:   "application/xml",
			accept: "application/xml",
			want:   false,
		},
		{
			name:   "*/* not first",
			accept: "application/json, */*",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tt.accept

			got := IsHTMLRequest(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsJSONRequest(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{
			name:   "empty accept header",
			accept: "",
			want:   false,
		},
		{
			name:   "application/json",
			accept: "application/json",
			want:   true,
		},
		{
			name:   "application/json with charset",
			accept: "application/json; charset=utf-8",
			want:   true,
		},
		{
			name:   "text/html",
			accept: "text/html",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tt.accept

			got := IsJSONRequest(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsXMLRequest(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{
			name:   "empty accept header",
			accept: "",
			want:   false,
		},
		{
			name:   "application/xml",
			accept: "application/xml",
			want:   true,
		},
		{
			name:   "text/html",
			accept: "text/html",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tt.accept

			got := IsXMLRequest(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetPreferredFormat(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   string
	}{
		{
			name:   "empty accept header",
			accept: "",
			want:   "html",
		},
		{
			name:   "application/json",
			accept: "application/json",
			want:   "json",
		},
		{
			name:   "application/xml",
			accept: "application/xml",
			want:   "xml",
		},
		{
			name:   "text/html",
			accept: "text/html",
			want:   "html",
		},
		{
			name:   "*/*",
			accept: "*/*",
			want:   "html",
		},
		{
			name:   "text/plain",
			accept: "text/plain",
			want:   "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tt.accept

			got := GetPreferredFormat(ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScopesContain(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		target string
		want   bool
	}{
		{
			name:   "empty scopes",
			scopes: []string{},
			target: "read",
			want:   false,
		},
		{
			name:   "contains",
			scopes: []string{"read", "write"},
			target: "read",
			want:   true,
		},
		{
			name:   "not contains",
			scopes: []string{"read", "write"},
			target: "admin",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScopesContain(tt.scopes, tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMergeScopesUnique(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string
	}{
		{
			name: "both empty",
			a:    []string{},
			b:    []string{},
			want: []string{},
		},
		{
			name: "a empty",
			a:    []string{},
			b:    []string{"read", "write"},
			want: []string{"read", "write"},
		},
		{
			name: "b empty",
			a:    []string{"read", "write"},
			b:    []string{},
			want: []string{"read", "write"},
		},
		{
			name: "no duplicates",
			a:    []string{"read"},
			b:    []string{"write"},
			want: []string{"read", "write"},
		},
		{
			name: "with duplicates",
			a:    []string{"read", "write"},
			b:    []string{"write", "admin"},
			want: []string{"read", "write", "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeScopesUnique(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseScopesFromHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   []string
	}{
		{
			name:   "empty header",
			header: "",
			want:   nil,
		},
		{
			name:   "single scope",
			header: "read",
			want:   []string{"read"},
		},
		{
			name:   "multiple scopes",
			header: "read,write,admin",
			want:   []string{"read", "write", "admin"},
		},
		{
			name:   "scopes with spaces",
			header: "read, write, admin",
			want:   []string{"read", "write", "admin"},
		},
		{
			name:   "empty entries",
			header: "read,,write",
			want:   []string{"read", "write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseScopesFromHeader(tt.header)
			assert.Equal(t, tt.want, got)
		})
	}
}

// mockResponseContext extends mockContext with response tracking for SendErrorResponse tests
type mockResponseContext struct {
	*mockContext
	statusCode     int
	contentType    string
	jsonResponse   interface{}
	stringResponse string
}

func newMockResponseContext() *mockResponseContext {
	return &mockResponseContext{
		mockContext: newMockContext(),
	}
}

func (c *mockResponseContext) Status(status int) Context {
	c.statusCode = status
	return c
}

func (c *mockResponseContext) JSON(v interface{}) error {
	c.jsonResponse = v
	return nil
}

func (c *mockResponseContext) SendString(s string) error {
	c.stringResponse = s
	return nil
}

func (c *mockResponseContext) Set(key, value string) {
	c.mockContext.Set(key, value)
	if key == "Content-Type" {
		c.contentType = value
	}
}

func (c *mockResponseContext) Context() context.Context {
	return context.Background()
}

func TestSendErrorResponse_JSON(t *testing.T) {
	ctx := newMockResponseContext()
	ctx.headers["Accept"] = "application/json"

	err := SendErrorResponse(ctx, 401, "Unauthorized")

	require.NoError(t, err)
	assert.Equal(t, 401, ctx.statusCode)
	assert.Equal(t, "application/json", ctx.contentType)
	assert.NotNil(t, ctx.jsonResponse)

	resp, ok := ctx.jsonResponse.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Unauthorized", resp["error"])
	assert.Equal(t, 401, resp["code"])
}

func TestSendErrorResponse_XML(t *testing.T) {
	ctx := newMockResponseContext()
	ctx.headers["Accept"] = "application/xml"

	err := SendErrorResponse(ctx, 403, "Forbidden")

	require.NoError(t, err)
	assert.Equal(t, 403, ctx.statusCode)
	assert.Equal(t, "application/xml", ctx.contentType)
	assert.Contains(t, ctx.stringResponse, "<errors>")
	assert.Contains(t, ctx.stringResponse, "Forbidden")
	assert.Contains(t, ctx.stringResponse, "403")
}

func TestSendErrorResponse_Text(t *testing.T) {
	ctx := newMockResponseContext()
	ctx.headers["Accept"] = "text/plain"

	err := SendErrorResponse(ctx, 500, "Internal Server Error")

	require.NoError(t, err)
	assert.Equal(t, 500, ctx.statusCode)
	assert.Equal(t, "text/plain", ctx.contentType)
	assert.Equal(t, "Internal Server Error", ctx.stringResponse)
}

func TestSendErrorResponse_HTML(t *testing.T) {
	// HTML requests get text/plain for errors
	ctx := newMockResponseContext()
	ctx.headers["Accept"] = "text/html"

	err := SendErrorResponse(ctx, 401, "Not Authorized")

	require.NoError(t, err)
	assert.Equal(t, 401, ctx.statusCode)
	// HTML format falls through to text
	assert.Equal(t, "text/plain", ctx.contentType)
}
