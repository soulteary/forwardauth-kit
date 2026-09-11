package forwardauth

import (
	"errors"
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
		SessionEnabled:            true,
		StepUpEnabled:             true,
		StepUpForwardedURITrusted: true,
		StepUpPaths:               []string{"/admin/*"},
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

// --- Codex review follow-ups (PR #4) ---

// TestStepUpMatchesForwardedPathWithQuery is the regression test for matching
// the raw X-Forwarded-Uri. The README's own nginx configuration passes
// $request_uri, which carries the query string, and StepUpMatcher anchors its
// pattern at both ends -- so an exact protected route such as
// /settings/security skipped step-up entirely whenever a query parameter was
// present.
func TestStepUpMatchesForwardedPathWithQuery(t *testing.T) {
	config := &Config{
		HeaderAuthEnabled:               true,
		HeaderAuthUserPhone:             "X-User-Phone",
		HeaderAuthAllowUntrustedHeaders: true,
		HeaderAuthCheckFunc:             func(string, string) bool { return true },
		StepUpEnabled:                   true,
		StepUpForwardedURITrusted:       true,
		StepUpPaths:                     []string{"/settings/security"},
		StepUpSessionKey:                "step_up_verified",
	}
	handler := NewHandler(config)

	for _, uri := range []string{
		"/settings/security",
		"/settings/security?tab=password",
		"/settings/security?a=1&b=2",
		"/settings/security#frag",
	} {
		ctx := newMockContext()
		ctx.headers["X-User-Phone"] = "1234567890"
		ctx.headers["X-Forwarded-Uri"] = uri

		_, err := handler.Check(ctx, nil)
		if !errors.Is(err, ErrStepUpRequired) {
			t.Errorf("X-Forwarded-Uri %q: err = %v, want ErrStepUpRequired -- step-up was skipped", uri, err)
		}
	}

	// An unprotected route is still unaffected.
	ctx := newMockContext()
	ctx.headers["X-User-Phone"] = "1234567890"
	ctx.headers["X-Forwarded-Uri"] = "/settings/profile?tab=password"
	if _, err := handler.Check(ctx, nil); errors.Is(err, ErrStepUpRequired) {
		t.Error("step-up fired on an unprotected route")
	}
}

// TestHeaderCheckerRefusesWithoutATrustDecision is the regression test for the
// trust gate living only in Config.Validate. Nothing forces a caller to run
// Validate -- NewHandler does not -- so a nil HeaderAuthTrustFunc meant the
// runtime path went on accepting client-supplied identity headers, which is
// exactly what the explicit-trust requirement was added to stop.
func TestHeaderCheckerRefusesWithoutATrustDecision(t *testing.T) {
	base := func() *Config {
		return &Config{
			HeaderAuthEnabled:   true,
			HeaderAuthUserPhone: "X-User-Phone",
			HeaderAuthCheckFunc: func(string, string) bool { return true },
		}
	}

	// No trust decision at all: refuse.
	ctx := newMockContext()
	ctx.headers["X-User-Phone"] = "1234567890"
	_, err := NewHeaderChecker(base()).Check(ctx, nil)
	if !errors.Is(err, ErrHeaderAuthTrustUnspecified) {
		t.Errorf("Check() err = %v, want ErrHeaderAuthTrustUnspecified -- client headers were accepted by default", err)
	}

	// Explicitly acknowledged: accepted.
	cfg := base()
	cfg.HeaderAuthAllowUntrustedHeaders = true
	ctx = newMockContext()
	ctx.headers["X-User-Phone"] = "1234567890"
	res, err := NewHeaderChecker(cfg).Check(ctx, nil)
	if err != nil || res == nil || !res.Authenticated {
		t.Errorf("with HeaderAuthAllowUntrustedHeaders: (%v, %v), want an authenticated result", res, err)
	}

	// A trust function is consulted, and its refusal skips rather than errors.
	cfg = base()
	cfg.HeaderAuthTrustFunc = func(Context) bool { return false }
	ctx = newMockContext()
	ctx.headers["X-User-Phone"] = "1234567890"
	res, err = NewHeaderChecker(cfg).Check(ctx, nil)
	if err != nil || res != nil {
		t.Errorf("untrusted hop: (%v, %v), want the checker skipped", res, err)
	}
}

// TestRefreshKeepsAnOmittedName: UserInfo.Name is explicitly optional, so a
// refresh callback returning only scopes and role legitimately leaves it
// empty. Replacing it unconditionally erased KeyUserName -- and the
// X-Auth-Name header with it -- after the first refresh.
func TestRefreshKeepsAnOmittedName(t *testing.T) {
	sess := newMockSession()
	sess.Set(KeyUserName, "Ada Lovelace")
	sess.Set(KeyUserScope, []string{"read", "write"})
	sess.Set(KeyUserRole, "admin")
	sess.Set(KeyUserPhone, "1234567890")

	config := &Config{
		HeaderAuthEnabled:               true,
		HeaderAuthUserPhone:             "X-User-Phone",
		HeaderAuthAllowUntrustedHeaders: true,
		HeaderAuthCheckFunc:             func(string, string) bool { return true },
		HeaderAuthGetInfoFunc: func(string, string) *UserInfo {
			// Authorization-only refresh: no Name.
			return &UserInfo{Scopes: []string{"read"}, Role: "user"}
		},
	}
	handler := NewHandler(config)

	ctx := newMockContext()
	ctx.headers["X-User-Phone"] = "1234567890"

	result := &AuthResult{Authenticated: true, NeedsRefresh: true}
	handler.refreshAuthInfo(ctx, sess, result)

	if got := sess.Get(KeyUserName); got != "Ada Lovelace" {
		t.Errorf("KeyUserName = %v after an authorization-only refresh, want it preserved", got)
	}
	if result.Name != "" && result.Name != "Ada Lovelace" {
		t.Errorf("result.Name = %q, want the existing name untouched", result.Name)
	}

	// Revocation semantics for scopes and role are unchanged.
	if got, ok := sess.Get(KeyUserScope).([]string); !ok || len(got) != 1 || got[0] != "read" {
		t.Errorf("KeyUserScope = %v, want the refreshed [read]", sess.Get(KeyUserScope))
	}
	if got := sess.Get(KeyUserRole); got != "user" {
		t.Errorf("KeyUserRole = %v, want the refreshed \"user\"", got)
	}
}

// --- Codex review round 2 (PR #4) ---

// TestUntrustedForwardedURICannotSkipStepUp is the regression test for taking
// X-Forwarded-Uri at face value. A proxy that forwards a client-supplied
// header rather than overwriting it -- Traefik with trustForwardHeader: true
// -- lets an authenticated client send "X-Forwarded-Uri: /public" and skip
// step-up on a protected route. Without an explicit declaration that the proxy
// overwrites the header, such a request is treated as protected.
func TestUntrustedForwardedURICannotSkipStepUp(t *testing.T) {
	newHandler := func(trusted bool) *Handler {
		return NewHandler(&Config{
			SessionEnabled:            true,
			StepUpEnabled:             true,
			StepUpPaths:               []string{"/admin/*"},
			StepUpSessionKey:          "step_up_verified",
			StepUpForwardedURITrusted: trusted,
		})
	}

	authed := func() *mockSession {
		sess := newMockSession()
		sess.data[KeyAuthenticated] = true
		return sess
	}

	// The forged claim: really hitting /admin/settings, claiming /public.
	ctx := newMockContext()
	ctx.path = "/_auth"
	ctx.headers["X-Forwarded-Uri"] = "/public"

	if _, err := newHandler(false).Check(ctx, authed()); !errors.Is(err, ErrStepUpRequired) {
		t.Errorf("untrusted forwarded URI: err = %v, want ErrStepUpRequired -- the client chose the target", err)
	}

	// A deployment whose proxy overwrites the header keeps the precise
	// behaviour: /public really is unprotected.
	if _, err := newHandler(true).Check(ctx, authed()); errors.Is(err, ErrStepUpRequired) {
		t.Error("trusted forwarded URI: step-up fired on an unprotected route")
	}

	// With no forwarded header at all there is nothing client-chosen to
	// distrust, so the fallback to the request path still applies.
	bare := newMockContext()
	bare.path = "/public"
	if _, err := newHandler(false).Check(bare, authed()); errors.Is(err, ErrStepUpRequired) {
		t.Error("step-up fired on an unprotected path with no forwarded header")
	}
}

// TestStepUpMatchesEncodedForwardedPath is the regression test for matching
// the forwarded URI byte-for-byte. A router decodes percent-escapes before
// routing -- net/http's ServeMux dispatches on the decoded URL.Path -- so
// "/%61dmin/settings" reaches the /admin handler while a "/admin/*" step-up
// pattern saw a path that started with "%61" and let the request through.
func TestStepUpMatchesEncodedForwardedPath(t *testing.T) {
	sess := newMockSession()
	sess.data[KeyAuthenticated] = true

	h := NewHandler(&Config{
		SessionEnabled:            true,
		StepUpEnabled:             true,
		StepUpForwardedURITrusted: true,
		StepUpPaths:               []string{"/admin/*"},
	})

	for _, uri := range []string{
		"/%61dmin/settings",          // the first letter escaped
		"/%61dmin/settings?tab=keys", // and with a query, as $request_uri sends
		"/admin/./settings",          // a dot segment
		"/public/../admin/settings",  // and a traversal
	} {
		t.Run(uri, func(t *testing.T) {
			ctx := newMockContext()
			ctx.path = "/_auth"
			ctx.headers["X-Forwarded-Uri"] = uri

			if _, err := h.Check(ctx, sess); err != ErrStepUpRequired {
				t.Errorf("Check() = %v, want ErrStepUpRequired; the router routes this to /admin", err)
			}
		})
	}

	// Decoding must not start demanding step-up for unprotected paths.
	ctx := newMockContext()
	ctx.path = "/_auth"
	ctx.headers["X-Forwarded-Uri"] = "/public/%70age?x=1"
	if _, err := h.Check(ctx, sess); err != nil {
		t.Errorf("Check() = %v, want success for an unprotected forwarded URI", err)
	}
}

// TestDocumentedHeaderAuthConfigCompiles pins the README's primary header-auth
// example to the actual API and to what it claims to do.
//
// The previous revision's example called c.RemoteIP(), which
// forwardauth.Context does not have, so the documented setup did not compile.
// It also rested on the network peer, which does not establish where
// X-User-Phone came from: the proxy forwards whatever the client sent unless
// it is configured to clear it. Checking a secret only the proxy can inject
// does establish it, and is what both READMEs now show.
func TestDocumentedHeaderAuthConfigCompiles(t *testing.T) {
	const proxySecret = "s3cr3t"

	h := NewHandler(&Config{
		HeaderAuthEnabled:   true,
		HeaderAuthUserPhone: "X-User-Phone",
		HeaderAuthUserMail:  "X-User-Mail",
		HeaderAuthTrustFunc: ProxySecretTrustFunc("X-Proxy-Secret", proxySecret),
		HeaderAuthCheckFunc: func(phone, mail string) bool {
			return phone == "13800000000"
		},
	})

	trusted := newMockContext()
	trusted.headers["X-Proxy-Secret"] = proxySecret
	trusted.headers["X-User-Phone"] = "13800000000"
	if _, err := h.Check(trusted, nil); err != nil {
		t.Errorf("Check() = %v, want success for headers carrying the proxy's secret", err)
	}

	// The same identity headers, straight from a client.
	forged := newMockContext()
	forged.headers["X-User-Phone"] = "13800000000"
	if _, err := h.Check(forged, nil); err == nil {
		t.Error("identity headers without the proxy's secret were believed")
	}
}

// TestProxySecretTrustFuncFailsClosed is the regression test for comparing the
// proxy secret by hand. subtle.ConstantTimeCompare("", "") returns 1, so an
// unset secret made the hand-written check in the READMEs trust a request that
// presented NO header -- and that request could then supply forged identity
// headers.
func TestProxySecretTrustFuncFailsClosed(t *testing.T) {
	none := newMockContext() // no X-Proxy-Secret at all

	if ProxySecretTrustFunc("X-Proxy-Secret", "")(none) {
		t.Error("an empty configured secret trusted a request carrying no header")
	}
	if ProxySecretTrustFunc("", "s3cr3t")(none) {
		t.Error("an empty header name trusted a request")
	}
	if ProxySecretTrustFunc("X-Proxy-Secret", "s3cr3t")(none) {
		t.Error("a request carrying no header was trusted")
	}

	empty := newMockContext()
	empty.headers["X-Proxy-Secret"] = ""
	if ProxySecretTrustFunc("X-Proxy-Secret", "")(empty) {
		t.Error("an empty secret matched an empty header")
	}

	wrong := newMockContext()
	wrong.headers["X-Proxy-Secret"] = "nope"
	if ProxySecretTrustFunc("X-Proxy-Secret", "s3cr3t")(wrong) {
		t.Error("a wrong secret was trusted")
	}

	right := newMockContext()
	right.headers["X-Proxy-Secret"] = "s3cr3t"
	if !ProxySecretTrustFunc("X-Proxy-Secret", "s3cr3t")(right) {
		t.Error("the correct secret was not trusted")
	}
}
