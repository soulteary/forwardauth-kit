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

	// A request with no forwarded header carries no target to match, so it is
	// protected too -- see TestEmptyForwardedURICannotSkipStepUp for why the
	// request's own path cannot stand in for one.
	bare := newMockContext()
	bare.path = "/public"
	if _, err := newHandler(false).Check(bare, authed()); !errors.Is(err, ErrStepUpRequired) {
		t.Errorf("no forwarded header: err = %v, want ErrStepUpRequired -- there is no target to call unprotected", err)
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

// --- Codex review round 5 (PR #4) ---

// TestHTMLDetectionAgreesWithPreferredFormat is the regression test for
// IsHTMLRequest honouring "*/*" only in first position while
// GetPreferredFormat honoured it anywhere.
//
// "Accept: application/x-custom, */*" made the two disagree:
// HandleNotAuthenticated skipped the login redirect because IsHTMLRequest said
// false, and SendErrorResponse then saw "html" -- for which it has no branch --
// and fell through to a plain-text 401.
func TestHTMLDetectionAgreesWithPreferredFormat(t *testing.T) {
	for _, tc := range []struct {
		accept string
		want   bool
	}{
		{"", true},
		{"text/html", true},
		{"*/*", true},
		{"text/html,application/xhtml+xml,*/*;q=0.8", true},

		// The reported case: an unsupported preference followed by a wildcard.
		{"application/x-custom, */*", true},

		// An earlier SUPPORTED non-HTML format still settles it.
		{"application/json, */*", false},
		{"application/xml, */*", false},
		{"application/json", false},
		{"text/plain", false},
	} {
		t.Run(tc.accept, func(t *testing.T) {
			ctx := newMockContext()
			if tc.accept != "" {
				ctx.headers["Accept"] = tc.accept
			}

			if got := IsHTMLRequest(ctx); got != tc.want {
				t.Errorf("IsHTMLRequest(%q) = %v, want %v", tc.accept, got, tc.want)
			}
			// The invariant: the two must never disagree.
			if got, format := IsHTMLRequest(ctx), GetPreferredFormat(ctx); got != (format == "html") {
				t.Errorf("IsHTMLRequest = %v but GetPreferredFormat = %q", got, format)
			}
		})
	}
}

// --- Codex review round 6 (PR #4) ---

// TestPreferredFormatHonoursQualityWeights is the regression test for the
// Accept header's q parameter being discarded.
//
// RFC 9110 12.4.2 defines q=0 as "not acceptable", so
// "Accept: application/json;q=0, text/html;q=1" asks for HTML and explicitly
// refuses JSON. Selecting the first RECOGNIZED media type answered "json" for
// it, and HandleNotAuthenticated then sent JSON -- the one format the client
// had ruled out -- instead of the login redirect.
func TestPreferredFormatHonoursQualityWeights(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
		want   string
	}{
		// The reported case.
		{"json refused, html wanted", "application/json;q=0, text/html;q=1", "html"},
		{"json refused, wildcard", "application/json;q=0, */*", "html"},

		// A weight that merely ranks, rather than refuses.
		{"json outranks html", "text/html;q=0.8, application/json;q=0.9", "json"},
		{"html outranks json", "application/json;q=0.3, text/html;q=0.7", "html"},
		{"exact beats wildcard", "application/json;q=0.9, */*;q=0.8", "json"},

		// The weight can sit behind another parameter.
		{"q after another parameter", "text/html;level=1;q=0, application/json", "json"},

		// Nothing acceptable at all.
		{"everything refused", "*/*;q=0", "text"},
		{"only refusals", "text/html;q=0, application/json;q=0, application/xml;q=0", "text"},

		// A malformed weight is ignored, not read as a refusal.
		{"malformed weight", "application/json;q=bogus", "json"},

		// Equal weights still resolve exactly as they did before.
		{"first named wins", "application/json, text/html", "json"},
		{"first named wins, reversed", "text/html, application/json", "html"},
		{"bare wildcard is html", "*/*", "html"},
		{"xml before json", "application/xml, application/json", "xml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.want {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.want)
			}
			// The invariant from round 5 must survive the rewrite.
			if got, format := IsHTMLRequest(ctx), GetPreferredFormat(ctx); got != (format == "html") {
				t.Errorf("IsHTMLRequest = %v but GetPreferredFormat = %q", got, format)
			}
		})
	}
}

// TestExplicitRefusalIsNotARequest: a q=0 names a type in order to REFUSE it,
// so reporting it as a request for that type inverts the client's meaning.
func TestExplicitRefusalIsNotARequest(t *testing.T) {
	for _, tc := range []struct {
		accept    string
		wantJSON  bool
		wantXMLed bool
	}{
		{"application/json", true, false},
		{"application/json;q=0", false, false},
		{"application/json;q=0.1", true, false},
		{"application/xml;q=0", false, false},
		{"application/xml", false, true},
		{"text/html, application/json", true, false},
		{"*/*", false, false}, // a wildcard still does not NAME either type
	} {
		t.Run(tc.accept, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := IsJSONRequest(ctx); got != tc.wantJSON {
				t.Errorf("IsJSONRequest(%q) = %v, want %v", tc.accept, got, tc.wantJSON)
			}
			if got := IsXMLRequest(ctx); got != tc.wantXMLed {
				t.Errorf("IsXMLRequest(%q) = %v, want %v", tc.accept, got, tc.wantXMLed)
			}
		})
	}
}

// --- Codex review round 7 (PR #4) ---

// TestAcceptParsingRespectsQuotedParameters is the regression test for
// splitting the Accept header on raw delimiters.
//
// A media-type parameter value may be a quoted-string (RFC 9110 5.6.6) and may
// contain the very characters that delimit the list. Splitting
// `text/html;profile="a,b";q=0, application/json;q=1` on a raw comma tore the
// HTML range in two, so its q=0 was lost, HTML was recorded at the default
// weight of 1, and the tie-break picked HTML -- redirecting a client that had
// explicitly refused it. Exactly the inversion the q parsing was added to stop,
// reached through the splitter instead.
func TestAcceptParsingRespectsQuotedParameters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
		want   string
	}{
		// The reported case.
		{"comma inside a quoted parameter", `text/html;profile="a,b";q=0, application/json;q=1`, "json"},

		// A semicolon inside the quotes must not start a new parameter
		// either, or the q that follows it is read as part of the value.
		{"semicolon inside a quoted parameter", `text/html;profile="a;b";q=0, application/json;q=1`, "json"},

		// An escaped quote must not end the quoted string early.
		{"escaped quote", `text/html;profile="a\",b";q=0, application/json;q=1`, "json"},

		// The quoted parameter must not stop a range from being honoured.
		{"quoted parameter, html wanted", `text/html;profile="a,b";q=1, application/json;q=0`, "html"},
		{"quoted parameter, no weights", `text/html;profile="a,b"`, "html"},

		// An unbalanced quote must not swallow the rest of the header. The
		// answer is JSON rather than HTML precisely BECAUSE the remainder is
		// parsed: the HTML range carries a profile this package cannot
		// produce, while the application/json that follows is exactly what
		// would be sent. Before the recovery this returned "html" by never
		// seeing the JSON at all.
		{"unbalanced quote", `text/html;profile="a, application/json`, "json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.want {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.want)
			}
			if got, format := IsHTMLRequest(ctx), GetPreferredFormat(ctx); got != (format == "html") {
				t.Errorf("IsHTMLRequest = %v but GetPreferredFormat = %q", got, format)
			}
		})
	}
}

// --- Codex review round 8 (PR #4) ---

// TestUnmatchedQuoteDoesNotSwallowLaterRanges is the regression test for
// splitOutsideQuotes never leaving quote state.
//
// An unmatched quote left inQuote set for the rest of the string, so every
// later delimiter was suppressed and one stray quote swallowed every
// subsequent media range: `text/html;q=0;profile="oops, application/json;q=1`
// parsed as a single refused HTML range and the JSON the client actually asked
// for disappeared, leaving "text".
//
// The round-7 unbalanced-quote case could not catch this -- it expected HTML
// either way, so the assertion held whether or not the remainder was parsed.
func TestUnmatchedQuoteDoesNotSwallowLaterRanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
		want   string
	}{
		// The reported case: HTML refused, JSON requested, quote never closed.
		{"refused html, unmatched quote", `text/html;q=0;profile="oops, application/json;q=1`, "json"},

		// The later range is reachable at all.
		{"unmatched quote then xml", `text/html;q=0;profile="oops, application/xml`, "xml"},

		// A stray quote in a range that is not refused still resolves.
		{"unmatched quote, html kept", `text/html;profile="oops, application/json;q=0`, "html"},

		// Well-formed quoting must keep working exactly as before.
		{"balanced still honoured", `text/html;profile="a,b";q=0, application/json;q=1`, "json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.want {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.want)
			}
			if got, format := IsHTMLRequest(ctx), GetPreferredFormat(ctx); got != (format == "html") {
				t.Errorf("IsHTMLRequest = %v but GetPreferredFormat = %q", got, format)
			}
		})
	}
}

// --- Codex review round 9 (PR #4) ---

// TestUnproducibleMediaParametersDoNotWinNegotiation is the regression test
// for discarding media-type parameters before selecting a format.
//
// RFC 9110 12.5.1: a media range's parameters narrow what it matches. This
// package's responses carry no parameters, so `application/json;profile=foo`
// is NOT matched by the bare `application/json` that would actually be sent --
// yet it was recorded as an exact match and won the negotiation, and
// SendErrorResponse then emitted `Content-Type: application/json` without the
// profile while a plainly-requested XML representation it could produce went
// unused.
func TestUnproducibleMediaParametersDoNotWinNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
		want   string
	}{
		// The reported case: XML is producible, the higher-weighted JSON is not.
		{"producible xml beats parameterized json", "application/xml;q=0.5, application/json;profile=foo;q=1", "xml"},
		{"producible json beats parameterized xml", "application/json;q=0.5, application/xml;version=2;q=1", "json"},

		// A parameter AFTER q is an accept-ext, not a media-type parameter, so
		// it must not disqualify the range.
		{"accept-ext after q is not a parameter", "application/xml;q=0.5, application/json;q=1;ext=1", "json"},

		// charset=utf-8 IS satisfied -- the output is UTF-8 -- so it must not
		// push a client onto its second choice.
		{"utf-8 charset is producible", "application/json;charset=utf-8, application/xml", "json"},
		{"quoted utf-8 charset", `application/json;charset="UTF-8", application/xml`, "json"},
		{"other charset is not", "application/json;charset=iso-8859-1, application/xml", "xml"},

		// When NOTHING is producible, the header is disregarded rather than
		// degrading every such client to plain text (RFC 9110 12.5.1 allows
		// this, and an HTML login redirect beats a text/plain 401).
		{"nothing producible falls back", `text/html;profile="a,b"`, "html"},
		{"nothing producible, html refused", "text/html;profile=x;q=0, application/json;profile=y", "json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.want {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.want)
			}
			if got, format := IsHTMLRequest(ctx), GetPreferredFormat(ctx); got != (format == "html") {
				t.Errorf("IsHTMLRequest = %v but GetPreferredFormat = %q", got, format)
			}
		})
	}
}

// --- Codex review round 10 (PR #4) ---

// TestParameterSpecificityOutranksHeaderOrder is the regression test for
// ranking two ranges of the same type/subtype by header order alone.
//
// RFC 9110 12.5.1 makes a range with more matching media-type parameters the
// more specific match. Since this package treats charset=utf-8 as satisfied,
// "application/json;charset=utf-8;q=0" is the more specific statement about
// JSON than a bare "application/json;q=1" -- so its refusal controls, and the
// answer is HTML. Ranking by position picked the earlier bare range and
// answered JSON, the one format the client had ruled out.
func TestParameterSpecificityOutranksHeaderOrder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
		want   string
	}{
		// The reported case.
		{"parameterized refusal controls", "application/json;q=1, application/json;charset=utf-8;q=0, text/html;q=0.5", "html"},

		// And the other way round: a parameterized ACCEPT outranks a bare refusal.
		{"parameterized acceptance controls", "application/json;q=0, application/json;charset=utf-8;q=1, text/html;q=0.5", "json"},

		// Order still decides when specificity ties.
		{"equal specificity keeps order", "application/json;q=1, application/json;q=0", "json"},

		// An exact type/subtype still outranks a wildcard carrying a
		// parameter: JSON takes its q from the exact range (1) rather than
		// from the wildcard (0), while HTML has only the wildcard's 0.
		{"exact beats parameterized wildcard", "*/*;charset=utf-8;q=0, application/json;q=1", "json"},

		// The converse, which is NOT a specificity question: a wildcard at a
		// higher weight than a specific range simply wins on weight, because
		// the specific range's own q is lower.
		{"weight still decides across shapes", "*/*;charset=utf-8;q=1, application/json;q=0.2", "html"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.want {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.want)
			}
			if got, format := IsHTMLRequest(ctx), GetPreferredFormat(ctx); got != (format == "html") {
				t.Errorf("IsHTMLRequest = %v but GetPreferredFormat = %q", got, format)
			}
		})
	}
}

// --- Codex review round 11 (PR #4) ---

// TestPredicatesUseTheSameRangePrecedence is the regression test for applying
// specificity in the negotiator but not in the exported predicates.
//
// IsJSONRequest/IsXMLRequest took the FIRST range naming the type, while
// GetPreferredFormat took the most specific one, so the two disagreed in both
// directions once a parameterized range was present -- a caller branching on
// IsJSONRequest and then calling SendErrorResponse would have got one answer
// from each.
func TestPredicatesUseTheSameRangePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		accept   string
		format   string
		wantJSON bool
	}{
		// The reported pair, both directions.
		{"specific acceptance wins", "application/json;q=0, application/json;charset=utf-8;q=1", "json", true},
		{"specific refusal wins", "application/json;q=1, application/json;charset=utf-8;q=0", "text", false},

		// Unchanged: a wildcard does not NAME the type, even at q=1.
		{"wildcard does not name", "*/*", "html", false},
		{"bare refusal", "application/json;q=0", "text", false},
		{"plain request", "text/html, application/json", "html", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.format {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.format)
			}
			if got := IsJSONRequest(ctx); got != tc.wantJSON {
				t.Errorf("IsJSONRequest(%q) = %v, want %v", tc.accept, got, tc.wantJSON)
			}
			// The invariant: whenever the negotiator settles on JSON, the
			// predicate must agree the client asked for it.
			if GetPreferredFormat(ctx) == "json" && !IsJSONRequest(ctx) {
				t.Errorf("GetPreferredFormat chose json but IsJSONRequest says the client did not ask for it")
			}
		})
	}
}

// TestXMLPredicateUsesTheSamePrecedence covers the other exported predicate.
func TestXMLPredicateUsesTheSamePrecedence(t *testing.T) {
	for _, tc := range []struct {
		accept  string
		wantXML bool
	}{
		{"application/xml;q=0, application/xml;charset=utf-8;q=1", true},
		{"application/xml;q=1, application/xml;charset=utf-8;q=0", false},
	} {
		t.Run(tc.accept, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept
			if got := IsXMLRequest(ctx); got != tc.wantXML {
				t.Errorf("IsXMLRequest(%q) = %v, want %v", tc.accept, got, tc.wantXML)
			}
		})
	}
}

// --- Codex review round 12 (PR #4) ---

// TestTypeWildcardsCountForThePredicates is the regression test for the
// predicates rejecting "application/*" while the negotiator accepted it.
//
// "Accept: application/*" makes GetPreferredFormat settle on JSON, but
// IsJSONRequest answered false, so a caller branching on the predicate and
// then calling SendErrorResponse got one answer from each. A type wildcard
// NAMES the type -- it narrows to that type's subtypes -- so it counts;
// "*/*" names nothing and still does not.
func TestTypeWildcardsCountForThePredicates(t *testing.T) {
	for _, tc := range []struct {
		accept   string
		format   string
		wantJSON bool
		wantXML  bool
	}{
		// The reported case.
		{"application/*", "json", true, true},

		// Weights still apply through the wildcard.
		{"application/*;q=0", "text", false, false},
		{"application/*;q=0, text/html", "html", false, false},

		// An exact range still outranks the type wildcard that covers it.
		{"application/*;q=1, application/json;q=0", "xml", false, true},

		// "*/*" names nothing: unchanged.
		{"*/*", "html", false, false},
		{"text/*", "html", false, false},
	} {
		t.Run(tc.accept, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.format {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.format)
			}
			if got := IsJSONRequest(ctx); got != tc.wantJSON {
				t.Errorf("IsJSONRequest(%q) = %v, want %v", tc.accept, got, tc.wantJSON)
			}
			if got := IsXMLRequest(ctx); got != tc.wantXML {
				t.Errorf("IsXMLRequest(%q) = %v, want %v", tc.accept, got, tc.wantXML)
			}
		})
	}
}

// TestGenericWildcardBoundaryIsDeliberate pins the one place the predicate and
// the negotiator still differ, so it stays a known property rather than
// becoming a surprise.
//
// With "*/*;q=1, text/html;q=0" the negotiator settles on JSON -- HTML is
// refused, and "*/*" covers JSON at q=1 -- while IsJSONRequest stays false
// because "*/*" names no type at all. Closing this would mean reporting that
// every `curl` default (`Accept: */*`) is a JSON request, which is a much
// wider behaviour change than the disagreement is worth.
func TestGenericWildcardBoundaryIsDeliberate(t *testing.T) {
	ctx := newMockContext()
	ctx.headers["Accept"] = "*/*;q=1, text/html;q=0"

	if got := GetPreferredFormat(ctx); got != "json" {
		t.Fatalf("GetPreferredFormat = %q, want json; the premise has changed", got)
	}
	if IsJSONRequest(ctx) {
		t.Error("IsJSONRequest now reports \"*/*\" as naming JSON -- confirm that is intended, " +
			"because it makes every Accept: */* a JSON request")
	}
}

// TestPredicatesRunTheSameTwoPassesAsTheNegotiator pins the reported case:
// "application/*;q=1, application/json;profile=foo;q=0".
//
// The negotiator drops the profile range it cannot honour before matching, so
// it sends JSON off "application/*". The predicates did not drop it, so the
// refusal -- the most specific range naming JSON -- won on shape and made
// IsJSONRequest say the client had not asked for the JSON it was about to be
// sent.
func TestPredicatesRunTheSameTwoPassesAsTheNegotiator(t *testing.T) {
	for _, tc := range []struct {
		accept   string
		format   string
		wantJSON bool
		wantXML  bool
	}{
		// The reported case. "application/*" is honourable and covers both
		// application subtypes; the q=0 refusal is not honourable and is gone
		// before either question is answered.
		{"application/*;q=1, application/json;profile=foo;q=0", "json", true, true},

		// Nothing honourable at all, so both fall back to the whole header
		// and read the same range.
		{"application/json;profile=foo", "json", true, false},
		{"application/json;profile=foo;q=0", "text", false, false},

		// A parameter this package does satisfy stays honourable, so the
		// more specific range still beats the earlier refusal.
		{"application/json;q=0, application/json;charset=utf-8;q=1", "json", true, false},

		// The honourable pass answers XML, but the client did name JSON --
		// with a profile that cannot be served. "Did the client ask for this
		// type?" is still yes; it is the negotiator, not the predicate, that
		// has to care whether the ask can be honoured.
		{"application/xml;q=0.5, application/json;profile=foo;q=1", "xml", true, true},
	} {
		t.Run(tc.accept, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.format {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.format)
			}
			if got := IsJSONRequest(ctx); got != tc.wantJSON {
				t.Errorf("IsJSONRequest(%q) = %v, want %v", tc.accept, got, tc.wantJSON)
			}
			if got := IsXMLRequest(ctx); got != tc.wantXML {
				t.Errorf("IsXMLRequest(%q) = %v, want %v", tc.accept, got, tc.wantXML)
			}
		})
	}
}

// TestChosenFormatIsAlwaysReportedAsAskedFor is the invariant behind the three
// predicate defects found so far: whatever GetPreferredFormat decides to send,
// the matching predicate has to agree the client asked for it. A handler that
// branches on IsJSONRequest and then lets SendErrorResponse pick the format
// otherwise takes the wrong branch for its own response.
//
// The converse does not hold, and deliberately: a client can name JSON in a
// way that cannot be served and still be sent something else.
func TestChosenFormatIsAlwaysReportedAsAskedFor(t *testing.T) {
	for _, accept := range []string{
		"application/*;q=1, application/json;profile=foo;q=0",
		"application/*;q=1, application/xml;profile=foo;q=0",
		"application/json;profile=foo",
		"application/json;q=0, application/json;charset=utf-8;q=1",
		"application/xml;q=0, application/xml;charset=utf-8;q=1",
		"application/json;profile=foo;q=1, application/json;q=0.1",
		"application/xml;q=0.5, application/json;profile=foo;q=1",
		"application/json, application/xml;q=0.9",
		"application/*",
		"application/*;q=0, application/json",
		"text/html;profile=foo, application/json;q=0.4",
	} {
		t.Run(accept, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = accept

			switch format := GetPreferredFormat(ctx); format {
			case "json":
				if !IsJSONRequest(ctx) {
					t.Errorf("GetPreferredFormat(%q) sends JSON but IsJSONRequest is false", accept)
				}
			case "xml":
				if !IsXMLRequest(ctx) {
					t.Errorf("GetPreferredFormat(%q) sends XML but IsXMLRequest is false", accept)
				}
			}
		})
	}
}

// --- Codex review round 13 (PR #4) ---

// TestEmptyForwardedURICannotSkipStepUp is the regression test for reading an
// empty X-Forwarded-Uri as an absent one.
//
// Context.Get answers "" for a header that was never sent and for one sent
// with an empty value alike -- Go's http.Header and Fiber both do -- so the
// round-2 guard, which only fired on a non-empty value, let an authenticated
// client send a bare "X-Forwarded-Uri:" and fall through to the request's own
// path. In a ForwardAuth deployment that path is the fixed auth endpoint, it
// matches no step-up pattern, and the answer was "not protected" for a request
// really targeting /admin/settings.
func TestEmptyForwardedURICannotSkipStepUp(t *testing.T) {
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

	for _, tc := range []struct {
		name     string
		trusted  bool
		path     string
		uri      string
		wantStep bool
	}{
		// The reported case, under both trust settings: a proxy that forwards
		// the client's header verbatim, and one declared to overwrite it but
		// that sent nothing to overwrite it with.
		{"untrusted empty value", false, "/_auth", "", true},
		{"trusted empty value", true, "/_auth", "", true},

		// The request path is never the target, whatever it says. Reaching for
		// it is the defect, so an unprotected-looking path does not rescue the
		// empty header.
		{"empty value on an unprotected path", true, "/public", "", true},

		// A value whose PATH component is empty is the same situation spelled
		// differently, and forwardedPath strips both of these to "".
		{"query only", true, "/_auth", "?tab=keys", true},
		{"fragment only", true, "/_auth", "#section", true},

		// The precision that has to survive: a trusted proxy naming a real
		// unprotected target still skips step-up.
		{"trusted unprotected target", true, "/_auth", "/public", false},
		{"trusted protected target", true, "/_auth", "/admin/settings", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newMockContext()
			ctx.path = tc.path
			ctx.headers["X-Forwarded-Uri"] = tc.uri

			_, err := newHandler(tc.trusted).Check(ctx, authed())
			if got := errors.Is(err, ErrStepUpRequired); got != tc.wantStep {
				t.Errorf("step-up required = %v, want %v (err = %v)", got, tc.wantStep, err)
			}
		})
	}
}

// TestEmptyStepUpPatternsProtectNothing pins the boundary of the fail-closed
// rule above: it applies only where a step-up control actually exists.
//
// StepUpEnabled with no usable StepUpPaths -- unset, empty, or all blank --
// builds a matcher with zero patterns, which RequiresStepUp answers false for
// on every path by definition. Failing closed on a missing forwarded target
// turned that into step-up on every route, so a configuration asking for
// step-up on nothing demanded it everywhere.
func TestEmptyStepUpPatternsProtectNothing(t *testing.T) {
	authed := func() *mockSession {
		sess := newMockSession()
		sess.data[KeyAuthenticated] = true
		return sess
	}

	for _, tc := range []struct {
		name  string
		paths []string
	}{
		{"unset", nil},
		{"empty", []string{}},
		{"blank entries", []string{"", "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(&Config{
				SessionEnabled:   true,
				StepUpEnabled:    true,
				StepUpPaths:      tc.paths,
				StepUpSessionKey: "step_up_verified",
			})
			if got := h.stepUpMatcher.PatternCount(); got != 0 {
				t.Fatalf("PatternCount() = %d, want 0; the premise has changed", got)
			}

			// The shape that fails closed when patterns DO exist: no usable
			// forwarded target, on the auth endpoint.
			ctx := newMockContext()
			ctx.path = "/_auth"
			ctx.headers["X-Forwarded-Uri"] = ""

			if _, err := h.Check(ctx, authed()); errors.Is(err, ErrStepUpRequired) {
				t.Error("step-up required with no protected paths configured")
			}
		})
	}

	// And the control: one real pattern restores the fail-closed rule.
	h := NewHandler(&Config{
		SessionEnabled:   true,
		StepUpEnabled:    true,
		StepUpPaths:      []string{"/admin/*"},
		StepUpSessionKey: "step_up_verified",
	})
	ctx := newMockContext()
	ctx.path = "/_auth"
	ctx.headers["X-Forwarded-Uri"] = ""
	if _, err := h.Check(ctx, authed()); !errors.Is(err, ErrStepUpRequired) {
		t.Errorf("err = %v, want ErrStepUpRequired once a path is protected", err)
	}
}

// --- Codex review round 15 (PR #4) ---

// TestUnsafeHeaderValuesAreDroppedNotSpliced is the regression test for
// repairing a header value by deleting the offending characters.
//
// strings.Map with -1 removes the rune and JOINS what surrounded it, so
// "ad\r\nmin" was emitted as "X-Auth-Role: admin" -- a malformed directory
// entry turned into the exact privileged token a downstream service
// authorizes. No character sequence should be able to become a DIFFERENT
// well-formed value on the way out; an unrepresentable value is dropped.
func TestUnsafeHeaderValuesAreDroppedNotSpliced(t *testing.T) {
	builder := NewAuthHeaderBuilder(&Config{
		UserHeaderName:   "X-Forwarded-User",
		AuthUserHeader:   "X-Auth-User",
		AuthEmailHeader:  "X-Auth-Email",
		AuthNameHeader:   "X-Auth-Name",
		AuthRoleHeader:   "X-Auth-Role",
		AuthScopesHeader: "X-Auth-Scopes",
		AuthAMRHeader:    "X-Auth-AMR",
	})

	for _, unsafe := range []string{
		"ad\r\nmin",              // the reported splice
		"ad\nmin",                // LF alone
		"ad\rmin",                // CR alone
		"ad\x00min",              // NUL
		"admin\r\nX-Injected: 1", // and the header-injection shape it came from
	} {
		t.Run(unsafe, func(t *testing.T) {
			headers := builder.BuildHeaders(&AuthResult{
				Authenticated: true,
				UserID:        unsafe,
				Email:         unsafe,
				Name:          unsafe,
				Role:          unsafe,
				Scopes:        []string{unsafe, "read"},
				AMR:           []string{unsafe, "pwd"},
			})

			for name, value := range headers {
				if strings.ContainsAny(value, "\r\n\x00") {
					t.Errorf("%s = %q still carries a control character", name, value)
				}
				// The splice, which is the actual defect: the value came out
				// as something the caller never held.
				if value == "admin" || strings.Contains(value, "adminX-Injected") {
					t.Errorf("%s = %q -- the unsafe value was spliced into a different one", name, value)
				}
			}

			// Dropped, not emitted empty or repaired.
			for _, name := range []string{"X-Auth-User", "X-Auth-Email", "X-Auth-Name", "X-Auth-Role"} {
				if got, ok := headers[name]; ok {
					t.Errorf("%s = %q, want the header to be absent", name, got)
				}
			}
			// The identity is unusable, so the request reads as authenticated
			// without naming anyone -- the same answer an empty UserID gets.
			if got := headers["X-Forwarded-User"]; got != "authenticated" {
				t.Errorf("X-Forwarded-User = %q, want %q", got, "authenticated")
			}
			// A safe sibling in the same list still survives.
			if got := headers["X-Auth-Scopes"]; got != "read" {
				t.Errorf("X-Auth-Scopes = %q, want %q", got, "read")
			}
			if got := headers["X-Auth-AMR"]; got != "pwd" {
				t.Errorf("X-Auth-AMR = %q, want %q", got, "pwd")
			}
		})
	}

	// The control: safe values are untouched, including ones with characters
	// that merely look suspicious.
	headers := builder.BuildHeaders(&AuthResult{
		Authenticated: true,
		UserID:        "user@example.com",
		Role:          "admin",
		Name:          "Ada Lovelace",
		Scopes:        []string{"read", "write"},
	})
	if got := headers["X-Auth-Role"]; got != "admin" {
		t.Errorf("X-Auth-Role = %q, want %q -- safe values must still pass", got, "admin")
	}
	if got := headers["X-Auth-Name"]; got != "Ada Lovelace" {
		t.Errorf("X-Auth-Name = %q, want %q", got, "Ada Lovelace")
	}
}

// countingSession records how many times a session was persisted.
type countingSession struct {
	*mockSession
	saves int
}

func (s *countingSession) Save() error {
	s.saves++
	return s.mockSession.Save()
}

// TestFailedRefreshSavesOnlyWhatItChanges is the regression test for writing
// the same cleared authorization on every request of an outage.
//
// KeyAuthRefreshedAt is deliberately not advanced when a refresh fails, so
// every subsequent request retries and lands in the clearing branch again.
// That branch saved unconditionally, so a directory outage became sustained
// write traffic against the session backend -- one write per request, all of
// them storing the empty scope and role already stored.
func TestFailedRefreshSavesOnlyWhatItChanges(t *testing.T) {
	handler := NewHandler(&Config{
		SessionEnabled:        true,
		AuthRefreshEnabled:    true,
		HeaderAuthGetInfoFunc: func(phone, mail string) *UserInfo { return nil },
	})

	sess := &countingSession{mockSession: newMockSession()}
	sess.data[KeyAuthenticated] = true
	sess.data[KeyUserPhone] = "1234567890"
	sess.data[KeyUserScope] = []string{"read", "write"}
	sess.data[KeyUserRole] = "admin"

	const requests = 25
	for i := 0; i < requests; i++ {
		result := &AuthResult{Authenticated: true}
		handler.refreshAuthInfo(newMockContext(), sess, result)

		// Every pass still clears, whether or not it writes.
		if result.Scopes != nil || result.Role != "" || !result.AuthRefreshFailed {
			t.Fatalf("request %d: authorization was not cleared: %+v", i, result)
		}
	}

	if sess.saves != 1 {
		t.Errorf("saves = %d over %d failed refreshes, want 1", sess.saves, requests)
	}
	if scopes, _ := sess.data[KeyUserScope].([]string); len(scopes) != 0 {
		t.Errorf("session scopes = %v, want empty", scopes)
	}
	if role, _ := sess.data[KeyUserRole].(string); role != "" {
		t.Errorf("session role = %q, want empty", role)
	}

	// Authorization coming back is a change again, and is persisted.
	sess.data[KeyUserRole] = "admin"
	handler.refreshAuthInfo(newMockContext(), sess, &AuthResult{Authenticated: true})
	if sess.saves != 2 {
		t.Errorf("saves = %d after authorization reappeared, want 2", sess.saves)
	}
}

// --- Codex review round 16 (PR #4) ---

// serializingSession models what almost every real session backend does to a
// []string: store it, and hand it back as a []interface{}. SessionChecker
// already reads both spellings; clearedAuthorization read only one.
type serializingSession struct {
	*mockSession
	saves int
}

func (s *serializingSession) Set(key string, value interface{}) {
	if scopes, ok := value.([]string); ok {
		boxed := make([]interface{}, 0, len(scopes))
		for _, scope := range scopes {
			boxed = append(boxed, scope)
		}
		s.mockSession.Set(key, boxed)
		return
	}
	s.mockSession.Set(key, value)
}

func (s *serializingSession) Save() error {
	s.saves++
	return s.mockSession.Save()
}

// TestFailedRefreshSavesOnceThroughASerializingBackend is the regression test
// for reading the cleared scope list back in only one of its two spellings.
//
// The failure path writes []string{}; a backend that serializes the session
// returns []interface{}{}. clearedAuthorization treated that as "not cleared",
// so the steady state after the first failure never LOOKED cleared and every
// later request wrote it again -- the sustained write traffic the previous
// commit was supposed to have stopped, still there for every deployment whose
// store round-trips through JSON.
func TestFailedRefreshSavesOnceThroughASerializingBackend(t *testing.T) {
	handler := NewHandler(&Config{
		SessionEnabled:        true,
		AuthRefreshEnabled:    true,
		HeaderAuthGetInfoFunc: func(phone, mail string) *UserInfo { return nil },
	})

	sess := &serializingSession{mockSession: newMockSession()}
	sess.mockSession.Set(KeyAuthenticated, true)
	sess.mockSession.Set(KeyUserPhone, "1234567890")
	sess.Set(KeyUserScope, []string{"read", "write"})
	sess.mockSession.Set(KeyUserRole, "admin")

	const requests = 25
	for i := 0; i < requests; i++ {
		result := &AuthResult{Authenticated: true}
		handler.refreshAuthInfo(newMockContext(), sess, result)
		if result.Scopes != nil || result.Role != "" || !result.AuthRefreshFailed {
			t.Fatalf("request %d: authorization was not cleared: %+v", i, result)
		}
	}

	if sess.saves != 1 {
		t.Errorf("saves = %d over %d failed refreshes through a serializing backend, want 1", sess.saves, requests)
	}

	// The stored value really is the boxed spelling -- otherwise this test
	// passes for the wrong reason.
	if _, ok := sess.data[KeyUserScope].([]interface{}); !ok {
		t.Fatalf("stored scopes are %T, want []interface{}; the premise has changed", sess.data[KeyUserScope])
	}

	// And a session still carrying scopes in that spelling is not cleared, so
	// the first failure after a revocation is still persisted.
	sess.saves = 0
	sess.Set(KeyUserScope, []string{"read"})
	handler.refreshAuthInfo(newMockContext(), sess, &AuthResult{Authenticated: true})
	if sess.saves != 1 {
		t.Errorf("saves = %d when boxed scopes were still present, want 1", sess.saves)
	}
}

// --- Codex review round 17 (PR #4) ---

// TestRefusalsSurviveTheFallbackPass is the regression test for the fallback
// overriding an explicit q=0.
//
// The fallback exists because a header naming only representations this
// package cannot produce is better disregarded than answered with 406 (RFC
// 9110 12.5.1). That is a concession for a question the client left
// UNANSWERED, and "q=0" is an answer: with "application/json;profile=foo;q=1,
// application/json;q=0" the honourable pass found nothing acceptable, the
// fallback took the profile range, and SendErrorResponse emitted bare
// application/json -- the one representation the client had refused.
//
// The same two ranges in the other order already answered "text", because at
// equal shape and equal satisfied-parameter count bestRange keeps whichever it
// saw first. So this also removes an order dependency: both spellings of the
// same header now answer the same thing.
func TestRefusalsSurviveTheFallbackPass(t *testing.T) {
	for _, tc := range []struct {
		accept   string
		format   string
		wantJSON bool
		wantXML  bool
	}{
		// The reported case, and the same header reordered.
		{"application/json;profile=foo;q=1, application/json;q=0", "text", false, false},
		{"application/json;q=0, application/json;profile=foo;q=1", "text", false, false},

		// The same shape for the other two formats.
		{"application/xml;profile=foo;q=1, application/xml;q=0", "text", false, false},
		{"text/html;profile=foo;q=1, text/html;q=0", "text", false, false},

		// A refusal reached through a wildcard is still a refusal: these
		// refuse every representation that would actually be sent.
		{"application/json;profile=foo;q=1, application/*;q=0", "text", false, false},
		{"application/json;profile=foo;q=1, */*;q=0", "text", false, false},

		// A refused format does not suppress an acceptable one. The honourable
		// pass answers here, so the fallback never runs.
		{"application/json;profile=foo;q=1, application/json;q=0, text/html;q=0.5", "html", false, false},

		// Controls. Nothing honourable at all is still an unanswered question,
		// so the fallback still applies...
		{"application/json;profile=foo", "json", true, false},
		// ...and a parameter this package satisfies still outranks an earlier
		// refusal, which is the round-9 behaviour.
		{"application/json;q=0, application/json;charset=utf-8;q=1", "json", true, false},
		// ...and an honourable range for ANOTHER type refuses nothing here.
		{"application/xml;q=0.5, application/json;profile=foo;q=1", "xml", true, true},
	} {
		t.Run(tc.accept, func(t *testing.T) {
			ctx := newMockContext()
			ctx.headers["Accept"] = tc.accept

			if got := GetPreferredFormat(ctx); got != tc.format {
				t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.format)
			}
			if got := IsJSONRequest(ctx); got != tc.wantJSON {
				t.Errorf("IsJSONRequest(%q) = %v, want %v", tc.accept, got, tc.wantJSON)
			}
			if got := IsXMLRequest(ctx); got != tc.wantXML {
				t.Errorf("IsXMLRequest(%q) = %v, want %v", tc.accept, got, tc.wantXML)
			}
		})
	}
}

// TestRefusalIsIndependentOfHeaderOrder pins the property behind the case
// above, rather than the two spellings that happened to be reported: a header
// and its reverse describe the same preferences, so they have to negotiate to
// the same representation.
func TestRefusalIsIndependentOfHeaderOrder(t *testing.T) {
	for _, pair := range [][2]string{
		{"application/json;profile=foo;q=1, application/json;q=0",
			"application/json;q=0, application/json;profile=foo;q=1"},
		{"application/xml;profile=foo;q=1, application/xml;q=0",
			"application/xml;q=0, application/xml;profile=foo;q=1"},
		{"application/json;profile=foo;q=1, application/*;q=0",
			"application/*;q=0, application/json;profile=foo;q=1"},
	} {
		forward, reversed := newMockContext(), newMockContext()
		forward.headers["Accept"] = pair[0]
		reversed.headers["Accept"] = pair[1]

		if a, b := GetPreferredFormat(forward), GetPreferredFormat(reversed); a != b {
			t.Errorf("GetPreferredFormat is order-dependent:\n  %q -> %q\n  %q -> %q", pair[0], a, pair[1], b)
		}
		if a, b := IsJSONRequest(forward), IsJSONRequest(reversed); a != b {
			t.Errorf("IsJSONRequest is order-dependent:\n  %q -> %v\n  %q -> %v", pair[0], a, pair[1], b)
		}
	}
}

// --- Codex review round 18 (PR #4) ---

// TestAllowUntrustedHeadersReallyAcceptsForgedIdentity pins what
// HeaderAuthAllowUntrustedHeaders does, because the READMEs described it
// wrongly and nothing failed.
//
// Both READMEs said the flag was "only safe when nothing but the proxy can
// reach this endpoint at all". Reachability is a different question and does
// not answer this one: a proxy that FORWARDS the client's identity headers
// relays whatever the client sent, so an endpoint nothing else can reach still
// authenticates a client as any user in the allow list. The requirement is
// that the proxy strips the client's headers and sets its own, which is what
// the Config comment already said and the READMEs now say too.
//
// This is a characterization test, not a fix: the behaviour below is the
// intended meaning of an explicit acknowledgement flag and has not changed.
// It exists so the documented claim is checkable rather than prose.
func TestAllowUntrustedHeadersReallyAcceptsForgedIdentity(t *testing.T) {
	// The header as a forwarding proxy would deliver it: written by the
	// client, relayed untouched.
	forged := newMockContext()
	forged.headers["X-User-Phone"] = "1234567890"

	inAllowList := func(phone, mail string) bool { return phone == "1234567890" }

	acknowledged := NewHandler(&Config{
		HeaderAuthEnabled:               true,
		HeaderAuthUserPhone:             "X-User-Phone",
		HeaderAuthAllowUntrustedHeaders: true,
		HeaderAuthCheckFunc:             inAllowList,
	})
	result, err := acknowledged.Check(forged, nil)
	if err != nil || result == nil || !result.Authenticated {
		t.Fatalf("HeaderAuthAllowUntrustedHeaders no longer accepts a client-supplied identity "+
			"(err = %v) -- if that is deliberate, the READMEs and Config comment need updating too", err)
	}

	// The alternative the READMEs point at first: a trust function, which
	// refuses the same request because it carries nothing only the proxy
	// could have produced.
	guarded := NewHandler(&Config{
		HeaderAuthEnabled:   true,
		HeaderAuthUserPhone: "X-User-Phone",
		HeaderAuthTrustFunc: ProxySecretTrustFunc("X-Proxy-Secret", "s3cret"),
		HeaderAuthCheckFunc: inAllowList,
	})
	if _, err := guarded.Check(forged, nil); err == nil {
		t.Error("a trust function accepted an identity header with no proxy secret")
	}

	// And accepts it once the proxy's secret is present.
	fromProxy := newMockContext()
	fromProxy.headers["X-User-Phone"] = "1234567890"
	fromProxy.headers["X-Proxy-Secret"] = "s3cret"
	result, err = guarded.Check(fromProxy, nil)
	if err != nil || result == nil || !result.Authenticated {
		t.Fatalf("a trust function rejected a request carrying the proxy secret (err = %v)", err)
	}
}

// --- Codex review round 19 (PR #4) ---

// TestTrustFuncDoesNotEstablishHeaderProvenance pins the distinction the
// documentation kept losing: a trust check establishes where a request came
// FROM, not who wrote the identity headers it carries.
//
// The Config comment used to offer stripping the headers and supplying
// HeaderAuthTrustFunc as two ways to do the same job -- "either ... or" --
// and described the callback as "typically by checking that the peer is a
// known proxy". Both readings fail against a proxy that injects its own
// marker and forwards the client's X-User-Phone unchanged: every forged
// request then has exactly the provenance the check looks for.
//
// A characterization test. Nothing here changed; what changed is that the
// claim is now checkable.
func TestTrustFuncDoesNotEstablishHeaderProvenance(t *testing.T) {
	inAllowList := func(phone, mail string) bool { return phone == "1234567890" }

	handler := NewHandler(&Config{
		HeaderAuthEnabled:   true,
		HeaderAuthUserPhone: "X-User-Phone",
		HeaderAuthTrustFunc: ProxySecretTrustFunc("X-Proxy-Secret", "s3cret"),
		HeaderAuthCheckFunc: inAllowList,
	})

	// A forwarding proxy: the client wrote the identity, the proxy added its
	// secret and passed the identity along untouched.
	forwarded := newMockContext()
	forwarded.headers["X-User-Phone"] = "1234567890" // written by the client
	forwarded.headers["X-Proxy-Secret"] = "s3cret"   // added by the proxy

	result, err := handler.Check(forwarded, nil)
	if err != nil || result == nil || !result.Authenticated {
		t.Fatalf("the premise has changed: a trust check now rejects a forwarded client identity (err = %v). "+
			"If HeaderAuthTrustFunc has started validating the headers themselves, the Config comments "+
			"and both READMEs need to say so", err)
	}

	// Which is why the stripping proxy is the control: once the identity
	// header is cleared, the same client value cannot reach the checker, and
	// the secret alone authenticates nobody.
	stripped := newMockContext()
	stripped.headers["X-User-Phone"] = "" // cleared by the proxy
	stripped.headers["X-Proxy-Secret"] = "s3cret"

	if _, err := handler.Check(stripped, nil); err == nil {
		t.Error("a request whose identity header the proxy cleared still authenticated")
	}
}

// --- Codex review round 21 (PR #4) ---

// TestQuotedPairsDecodeInParameterValues is the regression test for treating
// a backslash as an escape only before a quote.
//
// Inside a quoted-string a backslash escapes whatever octet follows it (RFC
// 9110 5.6.4). Unescaping just \" left charset="utf\-8" reading as the literal
// utf\-8, so a range naming a charset this package CAN honour was recorded as
// unhonourable and dropped from the honourable pass.
//
// splitOutsideQuotes already skipped the escaped octet when deciding where a
// value ends. The two halves of the rule now agree.
func TestQuotedPairsDecodeInParameterValues(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`"utf\-8"`, "utf-8"}, // the reported case: escaping an ordinary character
		{`"utf\"8"`, `utf"8`}, // an escaped quote, which already worked
		{`"a\\b"`, `a\b`},     // an escaped backslash, which did not
		{`"utf-8"`, "utf-8"},  // nothing to unescape
		{`utf-8`, "utf-8"},    // an unquoted token is untouched
		{`"a\"`, `a\`},        // malformed: a trailing backslash stands for itself
		{`""`, ""},            // empty quoted-string
		{`"\\"`, `\`},         // just an escaped backslash
	} {
		if got := unquoteParam(tc.in); got != tc.want {
			t.Errorf("unquoteParam(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// And what it means for negotiation: all three spellings of the same
	// charset are the same honourable range, so none of them loses to XML.
	for _, accept := range []string{
		`application/json;charset="utf\-8";q=1, application/xml;q=0.5`,
		`application/json;charset="utf-8";q=1, application/xml;q=0.5`,
		`application/json;charset=utf-8;q=1, application/xml;q=0.5`,
	} {
		ctx := newMockContext()
		ctx.headers["Accept"] = accept
		if got := GetPreferredFormat(ctx); got != "json" {
			t.Errorf("GetPreferredFormat(%q) = %q, want json -- the charset is one this package produces", accept, got)
		}
		if !IsJSONRequest(ctx) {
			t.Errorf("IsJSONRequest(%q) = false, want true", accept)
		}
	}
}

// --- Codex review round 22 (PR #4) ---

// TestUnmatchedQuoteOnlyDiscardsItsOwnTail is the regression test for the
// unmatched-quote recovery throwing away more than the malformed range.
//
// The recovery re-split the WHOLE header without quote awareness, so one
// stray quote late in a header corrupted every range before it:
// `text/html;profile="a,b";q=0, application/json;profile="oops` lost the HTML
// range's q=0 to the comma inside its own perfectly valid quoted string, and
// the refused HTML was what GetPreferredFormat returned.
//
// Parts already emitted were split on separators outside a BALANCED quoted
// string, so they are not in doubt. Only the unterminated tail is re-read.
func TestUnmatchedQuoteOnlyDiscardsItsOwnTail(t *testing.T) {
	t.Run("a valid prefix survives a malformed tail", func(t *testing.T) {
		ctx := newMockContext()
		ctx.headers["Accept"] = `text/html;profile="a,b";q=0, application/json;profile="oops`

		ranges := parseAccept(ctx.headers["Accept"])
		if len(ranges) != 2 {
			t.Fatalf("parsed %d ranges, want 2: %+v", len(ranges), ranges)
		}
		if ranges[0].quality != 0 {
			t.Errorf("the HTML range's q=0 was lost: quality = %v, want 0", ranges[0].quality)
		}
		if got := GetPreferredFormat(ctx); got != "json" {
			t.Errorf("GetPreferredFormat = %q, want json -- HTML was refused", got)
		}
	})

	// The case the recovery was added for still works: when the quote opens
	// before any separator, there is no valid prefix to keep and the whole
	// string is re-read.
	t.Run("no valid prefix to keep", func(t *testing.T) {
		ctx := newMockContext()
		ctx.headers["Accept"] = `text/html;q=0;profile="oops, application/json;q=1`

		if got := GetPreferredFormat(ctx); got != "json" {
			t.Errorf("GetPreferredFormat = %q, want json", got)
		}
	})
}

// TestQValueGrammarIsNarrowerThanAFloat is the regression test for reading a
// weight with strconv.ParseFloat.
//
//	qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
//
// ParseFloat accepted spellings that grammar excludes, so "q=1e-1" became a
// real priority of 0.1 and "application/json;q=1e-1, text/html;q=0.5"
// answered HTML off a weight the client never expressed. A malformed
// parameter is ignored, so the default weight of 1 stands and JSON wins.
func TestQValueGrammarIsNarrowerThanAFloat(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  float64
		valid bool
	}{
		// Valid spellings.
		{"0", 0, true}, {"1", 1, true},
		{"0.5", 0.5, true}, {"0.123", 0.123, true},
		{"1.0", 1, true}, {"1.000", 1, true},
		{"0.", 0, true}, {"1.", 1, true},

		// Numeric to ParseFloat, not a qvalue.
		{"1e-1", 0, false},   // the reported case
		{".5", 0, false},     // no leading digit
		{"0.1234", 0, false}, // more than three fractional digits
		{"1.001", 0, false},  // 1 admits only zeros
		{"1.5", 0, false},    // ...and this used to clamp to 1 silently
		{"2", 0, false}, {"-0.5", 0, false}, {"+1", 0, false},
		{"Inf", 0, false}, {"NaN", 0, false}, {"0x1", 0, false},
		{"", 0, false}, {"abc", 0, false},
	} {
		got, ok := parseQValue(tc.in)
		if ok != tc.valid {
			t.Errorf("parseQValue(%q) valid = %v, want %v", tc.in, ok, tc.valid)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("parseQValue(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	// What it means for negotiation: a malformed weight is ignored, so the
	// range keeps the default weight of 1 rather than gaining one the client
	// never wrote.
	for _, tc := range []struct{ accept, format string }{
		{"application/json;q=1e-1, text/html;q=0.5", "json"},
		{"application/json;q=.5, text/html;q=0.4", "json"},
		{"application/json;q=0.1234, text/html;q=0.5", "json"},
		// ...and a well-formed one still decides.
		{"application/json;q=0.1, text/html;q=0.5", "html"},
		{"application/json;q=0.123, text/html;q=0.5", "html"},
	} {
		ctx := newMockContext()
		ctx.headers["Accept"] = tc.accept
		if got := GetPreferredFormat(ctx); got != tc.format {
			t.Errorf("GetPreferredFormat(%q) = %q, want %q", tc.accept, got, tc.format)
		}
	}
}
