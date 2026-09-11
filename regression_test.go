package forwardauth

import (
	"strings"
	"testing"
)

// TestStepUpMatchesForwardedURI is the regression test for step-up matching the
// wrong path: in a ForwardAuth deployment the proxy calls a fixed endpoint and
// puts the real target in X-Forwarded-Uri, so matching c.Path() compared the
// patterns against "/_auth" and never fired.
func TestStepUpMatchesForwardedURI(t *testing.T) {
	sess := newMockSession()
	sess.data[KeyAuthenticated] = true

	h := NewHandler(&Config{
		SessionEnabled: true,
		StepUpEnabled:  true,
		StepUpPaths:    []string{"/admin/*"},
	})

	ctx := newMockContext()
	ctx.path = "/_auth" // where the proxy actually calls us
	ctx.headers["X-Forwarded-Uri"] = "/admin/secrets"

	if _, err := h.Check(ctx, sess); err != ErrStepUpRequired {
		t.Fatalf("Check() = %v, want ErrStepUpRequired for a protected forwarded URI", err)
	}

	ctx2 := newMockContext()
	ctx2.path = "/_auth"
	ctx2.headers["X-Forwarded-Uri"] = "/public/page"
	if _, err := h.Check(ctx2, sess); err != nil {
		t.Fatalf("Check() = %v, want success for an unprotected forwarded URI", err)
	}
}

// TestRefreshClearsRevokedAuthorization: an authorization refresh must be able
// to lower privileges, not only raise them.
func TestRefreshClearsRevokedAuthorization(t *testing.T) {
	t.Run("scopes revoked to none are cleared", func(t *testing.T) {
		sess := newMockSession()
		sess.data[KeyAuthenticated] = true
		sess.data[KeyUserMail] = "user@example.com"
		sess.data[KeyUserScope] = []string{"admin", "write"}
		sess.data[KeyUserRole] = "admin"

		h := NewHandler(&Config{
			SessionEnabled:        true,
			AuthRefreshEnabled:    true,
			HeaderAuthGetInfoFunc: func(string, string) *UserInfo { return &UserInfo{Scopes: nil, Role: ""} },
		})

		result, err := h.Check(newMockContext(), sess)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}
		if len(result.Scopes) != 0 {
			t.Errorf("scopes = %v, want empty after revocation", result.Scopes)
		}
		if result.Role != "" {
			t.Errorf("role = %q, want empty after revocation", result.Role)
		}
	})

	t.Run("directory lookup failure drops cached authorization", func(t *testing.T) {
		sess := newMockSession()
		sess.data[KeyAuthenticated] = true
		sess.data[KeyUserMail] = "user@example.com"
		sess.data[KeyUserScope] = []string{"admin"}

		h := NewHandler(&Config{
			SessionEnabled:        true,
			AuthRefreshEnabled:    true,
			HeaderAuthGetInfoFunc: func(string, string) *UserInfo { return nil },
		})

		result, err := h.Check(newMockContext(), sess)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}
		if len(result.Scopes) != 0 {
			t.Errorf("scopes = %v, want empty when the user could not be looked up", result.Scopes)
		}
		if !result.AuthRefreshFailed {
			t.Error("AuthRefreshFailed = false, want true so callers can fail the request")
		}
	})
}

// TestScopeSeparatorCannotBeInjected: BuildHeaders joins on "," and
// ParseScopesFromHeader splits on it, so a value carrying the separator would
// mint extra permissions downstream.
func TestScopeSeparatorCannotBeInjected(t *testing.T) {
	b := NewAuthHeaderBuilder(&Config{
		AuthScopesHeader: "X-Auth-Scopes",
		AuthRoleHeader:   "X-Auth-Role",
		UserHeaderName:   "X-Forwarded-User",
		AuthUserHeader:   "X-Auth-User",
	})

	headers := b.BuildHeaders(&AuthResult{
		Authenticated: true,
		UserID:        "u1",
		Scopes:        []string{"read", "read,admin", "write"},
	})

	got := headers["X-Auth-Scopes"]
	for _, s := range ParseScopesFromHeader(got) {
		if s == "admin" {
			t.Fatalf("scope header %q parses back to include an injected \"admin\"", got)
		}
	}
	if got != "read,write" {
		t.Errorf("scopes header = %q, want %q", got, "read,write")
	}
}

// TestHeaderValuesCannotBreakOutOfTheField guards against CR/LF in values.
func TestHeaderValuesCannotBreakOutOfTheField(t *testing.T) {
	b := NewAuthHeaderBuilder(&Config{
		UserHeaderName: "X-Forwarded-User",
		AuthUserHeader: "X-Auth-User",
		AuthNameHeader: "X-Auth-Name",
	})

	headers := b.BuildHeaders(&AuthResult{
		Authenticated: true,
		UserID:        "u1",
		Name:          "evil\r\nX-Admin: true",
	})

	for k, v := range headers {
		if strings.ContainsAny(v, "\r\n") {
			t.Errorf("header %s carries a control character: %q", k, v)
		}
	}
}

// TestNormalizeHostHandlesIPv6: strings.Index(host, ":") truncated a bracketed
// IPv6 literal to "[".
func TestNormalizeHostHandlesIPv6(t *testing.T) {
	cases := map[string]string{
		"example.com:8080": "example.com",
		"example.com":      "example.com",
		"[::1]:8080":       "::1",
		"[::1]":            "::1",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
