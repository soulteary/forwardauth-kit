# forwardauth-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/forwardauth-kit/v2.svg)](https://pkg.go.dev/github.com/soulteary/forwardauth-kit/v2)
[![Go Report Card](.github/goreportcard.svg)](.github/goreportcard-report.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/forwardauth-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/forwardauth-kit)

[中文文档](README_CN.md)

A Go library providing ForwardAuth middleware for reverse proxy authentication. Supports multiple authentication methods and integrates with session management for use with Traefik, Nginx, and other reverse proxies.

## Features

- **Multiple Authentication Methods**: Password, Header-based (Warden), and Session authentication
- **Priority-based Checker Chain**: Configurable authentication method priority
- **Step-up Authentication**: Support for sensitive path protection with additional authentication
- **Auth Refresh**: Automatic refresh of user authorization information
- **Flexible Header Mapping**: Customizable authentication response headers
- **Framework Agnostic**: Core logic is framework-independent with Fiber adapter included
- **Cross-domain Support**: Cookie utilities for cross-domain authentication flows

## Requirements

- **Go 1.27+** (`go.mod` declares `go 1.27.0`)
- Fiber v3.4.0 or later for the `Fiber*` adapters; the core is framework-agnostic

## Installation

```bash
go get github.com/soulteary/forwardauth-kit/v2
```

Fiber integrations require Fiber v3.4.0 or later. Applications that still use Fiber v2 should remain on `github.com/soulteary/forwardauth-kit` v1.

## Quick Start

### Basic Fiber Integration

```go
package main

import (
    "github.com/gofiber/fiber/v3"
    "github.com/gofiber/fiber/v3/middleware/session"
    forwardauth "github.com/soulteary/forwardauth-kit/v2"
)

func main() {
    app := fiber.New()
    store := session.NewStore()

    // Configure ForwardAuth
    config := forwardauth.Config{
        SessionEnabled: true,
        AuthHost:       "auth.example.com",
        LoginPath:      "/_login",
    }

    handler := forwardauth.NewHandler(&config)

    // Register ForwardAuth check route
    app.All("/_auth", forwardauth.FiberCheckRoute(handler, store))

    app.Listen(":3000")
}
```

### Password Authentication

```go
config := forwardauth.Config{
    PasswordEnabled: true,
    PasswordHeader:  "Stargate-Password",
    // PLAINTEXT values, compared in constant time. These are not hashes.
    // They must be stored already normalized (see below) or nothing matches.
    ValidPasswords: []string{"ACCESSCODE1", "ACCESSCODE2"},
}

handler := forwardauth.NewHandler(&config)
```

**The default normalizer upper-cases and strips spaces**, which makes the
comparison case-insensitive and throws away entropy you may believe you have.
It is shaped for invite and access codes (`"ABCD 1234"`), not for passwords.
For real passwords, supply your own:

```go
config.PasswordNormalizer = strings.TrimSpace // or nil for no normalization
```

To verify against hashes instead of a plaintext list, use `PasswordCheckFunc`:

```go
config := forwardauth.Config{
    PasswordEnabled: true,
    PasswordCheckFunc: func(password string) bool {
        return bcrypt.CompareHashAndPassword(stored, []byte(password)) == nil
    },
}
```

`Config.Validate()` rejects `PasswordEnabled` with neither `ValidPasswords` nor
`PasswordCheckFunc` set.

### Header-based Authentication (Warden Integration)

```go
config := forwardauth.Config{
    HeaderAuthEnabled:   true,
    HeaderAuthUserPhone: "X-User-Phone",
    HeaderAuthUserMail:  "X-User-Mail",

    // REQUIRED. The identity headers are a claim, not a credential: anything
    // that can reach this endpoint can set them. Say which requests may be
    // believed.
    //
    // Check something only the proxy can produce. A shared secret it injects
    // works; the network peer alone does NOT, because being connected by the
    // proxy says nothing about who wrote X-User-Phone -- the proxy forwards
    // whatever the client sent unless it is configured to clear it. See the
    // nginx example below, which does both halves.
    // Trusts nothing if proxySecret is empty, and nothing that fails to
    // present the header. Do NOT hand-roll this comparison:
    // subtle.ConstantTimeCompare("", "") is 1, so an unset secret would
    // trust every request, header or not.
    HeaderAuthTrustFunc: forwardauth.ProxySecretTrustFunc("X-Proxy-Secret", proxySecret),
    // ...or acknowledge explicitly that any caller may supply them. This is
    // only safe when the proxy STRIPS the client's identity headers and sets
    // its own; reachability is a different question and does not answer this
    // one. A proxy that merely forwards them -- Traefik's trustForwardHeader,
    // or any proxy_pass that does not clear them -- relays whatever the client
    // sent, so even an endpoint nothing else can reach will authenticate a
    // client as any user in the allow list:
    //   HeaderAuthAllowUntrustedHeaders: true,

    HeaderAuthCheckFunc: func(phone, mail string) bool {
        // Check if user exists in allow list
        return wardenClient.CheckUserInList(phone, mail)
    },
    HeaderAuthGetInfoFunc: func(phone, mail string) *forwardauth.UserInfo {
        // Get full user info for headers
        user := wardenClient.GetUser(phone, mail)
        if user == nil {
            return nil
        }
        return &forwardauth.UserInfo{
            UserID: user.ID,
            Email:  user.Email,
            Phone:  user.Phone,
            Scopes: user.Scopes,
            Role:   user.Role,
        }
    },
}

handler := forwardauth.NewHandler(&config)
```

### Step-up Authentication

Step-up matches `StepUpPaths` against the **original request target**, which a
ForwardAuth proxy passes in `X-Forwarded-Uri` — not against the auth endpoint's
own path. Matching falls back to `Context.Path()` when no forwarded URI is
present, so direct (non-proxied) use works unchanged.

```go
config := forwardauth.Config{
    SessionEnabled:   true,
    StepUpEnabled:    true,
    StepUpPaths:      []string{"/admin/*", "/settings/security"},
    // REQUIRED when the proxy passes X-Forwarded-Uri. Step-up matches the
    // ORIGINAL target, which arrives in that header; set this only if the
    // proxy OVERWRITES it (nginx `proxy_set_header X-Forwarded-Uri
    // $request_uri` does). A proxy that merely forwards a client-supplied
    // value -- Traefik's trustForwardHeader: true -- lets a client send
    // "X-Forwarded-Uri: /public" and skip step-up, so when this is false any
    // request carrying the header is treated as protected. A request with no
    // usable forwarded path -- header absent, empty, or query-only -- is
    // treated as protected under either setting, because there is no target
    // to match and the auth endpoint's own path is not one.
    StepUpForwardedURITrusted: true,
    StepUpURL:        "/_step_up",
    StepUpSessionKey: "step_up_verified",
}

handler := forwardauth.NewHandler(&config)
```

### Auth Info Refresh

```go
config := forwardauth.Config{
    SessionEnabled:      true,
    HeaderAuthEnabled:   true,
    AuthRefreshEnabled:  true,
    AuthRefreshInterval: 5 * time.Minute,
    HeaderAuthGetInfoFunc: func(phone, mail string) *forwardauth.UserInfo {
        // Return nil to signal that the lookup failed or the account is gone.
        return getUserFromWarden(phone, mail)
    },
}

handler := forwardauth.NewHandler(&config)
```

A refresh **replaces** the cached scopes and role rather than merging into them,
so revoking a user's scopes to none, or clearing their role, takes effect. When
`HeaderAuthGetInfoFunc` returns `nil` the cached scopes and role are cleared and
`AuthResult.AuthRefreshFailed` is set — check it and reject the request if a
directory outage must not leave a deleted or suspended account with access:

```go
result, err := handler.Check(c, sess)
if err != nil {
    return err
}
if result.AuthRefreshFailed {
    // The directory could not confirm this user. Fail closed.
    return forwardauth.SendErrorResponse(c, http.StatusForbidden, "authorization unavailable")
}
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `SessionEnabled` | bool | true | Enable session-based authentication |
| `PasswordEnabled` | bool | false | Enable password header authentication |
| `PasswordHeader` | string | "Stargate-Password" | Header name for password |
| `ValidPasswords` | []string | - | List of valid password hashes |
| `PasswordCheckFunc` | func | - | Custom password validation function |
| `HeaderAuthEnabled` | bool | false | Enable header-based authentication |
| `HeaderAuthUserPhone` | string | "X-User-Phone" | Header name for phone |
| `HeaderAuthUserMail` | string | "X-User-Mail" | Header name for email |
| `HeaderAuthCheckFunc` | func | - | User existence check function |
| `HeaderAuthGetInfoFunc` | func | - | User info retrieval function |
| `StepUpEnabled` | bool | false | Enable step-up authentication |
| `StepUpPaths` | []string | - | Glob patterns for protected paths |
| `StepUpURL` | string | "/_step_up" | Step-up verification URL |
| `StepUpSessionKey` | string | "step_up_verified" | Session key for step-up flag |
| `StepUpForwardedURITrusted` | bool | false | The proxy overwrites `X-Forwarded-Uri`; when false, any request carrying it is treated as protected. A request with no usable forwarded path is protected either way |
| `HeaderAuthTrustFunc` | func(Context) bool | nil | Which requests may supply identity headers. Required unless `HeaderAuthAllowUntrustedHeaders` is set. A layer on top of the proxy stripping them, not a replacement -- it establishes where the request came from, not who wrote the headers |
| `HeaderAuthAllowUntrustedHeaders` | bool | false | Accept identity headers from any caller. Only safe when the proxy strips the client's and sets its own -- an isolated endpoint behind a *forwarding* proxy is still forgeable |
| `AuthRefreshEnabled` | bool | false | Enable auth info refresh |
| `AuthRefreshInterval` | Duration | 5m | Interval between refreshes |
| `UserHeaderName` | string | "X-Forwarded-User" | Primary user header |
| `AuthUserHeader` | string | "X-Auth-User" | User ID header |
| `AuthEmailHeader` | string | "X-Auth-Email" | Email header |
| `AuthScopesHeader` | string | "X-Auth-Scopes" | Scopes header (comma-separated) |
| `AuthRoleHeader` | string | "X-Auth-Role" | Role header |
| `AuthAMRHeader` | string | "X-Auth-AMR" | AMR header (comma-separated) |
| `AuthHost` | string | - | Authentication service host |
| `LoginPath` | string | "/_login" | Login page path |
| `CallbackParam` | string | "callback" | Callback query parameter |

## Response Headers

On successful authentication, the following headers are set:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Forwarded-User` | User identifier or "authenticated" | `user-123` |
| `X-Auth-User` | User ID | `user-123` |
| `X-Auth-Email` | User email | `user@example.com` |
| `X-Auth-Scopes` | Comma-separated scopes | `read,write,admin` |
| `X-Auth-Role` | User role | `admin` |
| `X-Auth-AMR` | Authentication methods used | `otp,mfa` |

Emitted header values are sanitised: CR and LF are stripped, and a scope or AMR
value containing a comma is dropped rather than emitted — `X-Auth-Scopes` is
comma-separated, so a scope like `read,admin` would otherwise mint an extra
permission downstream. Parse the header back with `ParseScopesFromHeader`.

## Auth Result

```go
type AuthResult struct {
    Authenticated     bool
    UserID            string
    Phone             string
    Email             string
    Name              string
    Role              string
    Scopes            []string
    AMR               []string
    AuthMethod        AuthMethod
    NeedsRefresh      bool
    RefreshedAt       time.Time
    AuthRefreshFailed bool // the directory lookup failed; fail closed
}
```

Scope helpers:

```go
forwardauth.ScopesContain(result.Scopes, "admin")
forwardauth.MergeScopesUnique(a, b)
forwardauth.ParseScopesFromHeader("read,write,admin")
```

## Errors

| Sentinel | Meaning |
|----------|---------|
| `ErrHeaderAuthTrustUnspecified` | `HeaderAuthEnabled` is set but neither `HeaderAuthTrustFunc` nor `HeaderAuthAllowUntrustedHeaders` was provided. Returned by `Config.Validate()` — the decision cannot be defaulted safely. |
| `ErrInvalidConfig` | The configuration is not usable |
| `ErrNotAuthenticated` | No checker authenticated the request |
| `ErrInvalidPassword` | The password checker rejected the value |
| `ErrForbidden` | Authenticated but not permitted |

Call `Config.Validate()` at startup so a missing trust decision fails the
process rather than silently trusting client-supplied identity headers.

## Response Format Helpers

```go
forwardauth.IsJSONRequest(c)
forwardauth.IsXMLRequest(c)
forwardauth.IsHTMLRequest(c)
forwardauth.GetPreferredFormat(c)          // "json" | "xml" | "html"
forwardauth.SendErrorResponse(c, 403, msg) // message is escaped for the chosen format
forwardauth.NormalizeHost("[::1]:8080")    // "[::1]"
```

## Custom Checkers

Implement the `AuthChecker` interface to add custom authentication methods:

```go
type CustomChecker struct {
    config *forwardauth.Config
}

func (c *CustomChecker) Check(ctx forwardauth.Context, sess forwardauth.Session) (*forwardauth.AuthResult, error) {
    // Custom authentication logic
    token := ctx.Get("Authorization")
    if token == "" {
        return nil, nil // Skip to next checker
    }

    // Validate token...
    if valid {
        return &forwardauth.AuthResult{
            Authenticated: true,
            UserID:        "user-123",
            AuthMethod:    forwardauth.AuthMethodToken,
        }, nil
    }
    return nil, forwardauth.ErrNotAuthenticated
}

func (c *CustomChecker) Priority() int { return 5 } // Higher priority than password (10)
func (c *CustomChecker) Name() string { return "custom" }

// Add to handler
handler.AddChecker(&CustomChecker{config: &config})
```

## Traefik Configuration

```yaml
http:
  middlewares:
    auth:
      forwardAuth:
        address: "http://auth-service:3000/_auth"
        trustForwardHeader: true
        authResponseHeaders:
          - "X-Forwarded-User"
          - "X-Auth-User"
          - "X-Auth-Email"
          - "X-Auth-Scopes"
          - "X-Auth-Role"
          - "X-Auth-AMR"

  routers:
    my-router:
      rule: "Host(`app.example.com`)"
      middlewares:
        - auth
      service: my-service
```

## Nginx Configuration

```nginx
location / {
    auth_request /_auth;
    auth_request_set $auth_user $upstream_http_x_auth_user;
    auth_request_set $auth_email $upstream_http_x_auth_email;
    
    proxy_set_header X-Auth-User $auth_user;
    proxy_set_header X-Auth-Email $auth_email;
    proxy_pass http://backend;
}

location = /_auth {
    internal;

    # Define the secret. Template it in at deploy time (envsubst, Ansible,
    # a Helm value) -- $proxy_secret is not a built-in nginx variable, and
    # nginx refuses to start if it is only referenced.
    set $proxy_secret "REPLACE_WITH_A_LONG_RANDOM_STRING";

    proxy_pass http://auth-service:3000/_auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Uri $request_uri;

    # The secret HeaderAuthTrustFunc checks. Keep it out of the client-facing
    # location block so a client can never send it.
    proxy_set_header X-Proxy-Secret $proxy_secret;

    # CLEAR the identity headers. Without this the client supplies its own
    # X-User-Phone / X-User-Mail, nginx forwards them unchanged, and the
    # trust check passes on a request whose identity the client forged.
    # Overwrite them from something you established yourself, or empty them.
    proxy_set_header X-User-Phone "";
    proxy_set_header X-User-Mail "";
}
```

`X-Forwarded-For` is client-supplied too: nginx APPENDS to whatever arrived, so
its leading entries are whatever the client chose. Use `$remote_addr`, not the
header, if you need the peer address -- and note that `forwardauth.Context`
does not expose it, so a peer-address check has to happen in your adapter
before the handler runs.

## Upgrade Notes (v2.2.0)

**This release can fail your startup on purpose.** With `HeaderAuthEnabled`
set, `Config.Validate()` now returns `ErrHeaderAuthTrustUnspecified` unless you
provide either `HeaderAuthTrustFunc` or `HeaderAuthAllowUntrustedHeaders`.

- **Identity headers now require an explicit trust decision.** `HeaderChecker`
  authenticates on `X-User-Phone` / `X-User-Mail` whenever the value is in the
  allow list, at a higher priority than the session checker — and anything that
  can reach this endpoint can set those headers. Neither the README's old nginx
  sample nor Traefik's `trustForwardHeader` strips custom headers a client sent.
  The package cannot know your trusted proxies, so the decision is yours to
  state: `ProxySecretTrustFunc("X-Proxy-Secret", secret)` checks something only
  the proxy can produce, or `HeaderAuthAllowUntrustedHeaders: true` acknowledges
  that any caller may supply them. **Update your nginx/Traefik config as well**
  — the sample now clears the identity headers and injects the secret.
- **Step-up authentication now actually fires.** Patterns were matched against
  `Context.Path()`, which in a ForwardAuth deployment is the fixed auth endpoint
  (`/_auth`), so `StepUpPaths` matched nothing and step-up was silently inert on
  every protected path. Matching now uses the forwarded URI. **If you had
  `StepUpEnabled` set, step-up will start challenging requests it previously let
  through.** Set `StepUpForwardedURITrusted: true` only if your proxy
  *overwrites* `X-Forwarded-Uri`; when it is false, any request carrying the
  header is treated as protected.
- **An authorization refresh can now lower privileges.** It merged rather than
  replaced, so revoking scopes to none or clearing a role left the old values in
  the session for its whole life. A failed lookup only logged, leaving a deleted
  account its access for as long as the lookup kept failing. The refresh now
  replaces, and a `nil` result clears the cached scopes and role and sets the new
  `AuthResult.AuthRefreshFailed`.
- **A scope containing a comma no longer mints extra permissions.**
  `BuildHeaders` joined scopes and AMR with `,` while `ParseScopesFromHeader`
  splits on it. Such values are dropped now, and CR/LF is stripped from every
  emitted header value.
- **Escaping fixes.** The step-up redirect interpolated the callback URL — which
  contains `://` and its own query string — into a query parameter unescaped, and
  `SendErrorResponse` interpolated the message into XML markup unescaped.
- **`NormalizeHost` handles IPv6.** It used `strings.Index(host, ":")`, which
  truncated `[::1]:8080` to `[`. It uses `net.SplitHostPort` now.
- **`ValidPasswords` is documented as plaintext**, which it always was despite
  the field comment and the README example calling the values hashes. The default
  password normalizer upper-cases, making the comparison case-insensitive; supply
  `PasswordNormalizer` for real passwords.

## Testing

```bash
go test ./...

# With coverage
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -func=coverage.out
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
