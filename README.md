# forwardauth-kit

A Go library providing ForwardAuth middleware for reverse proxy authentication. Supports multiple authentication methods and integrates with session management for use with Traefik, Nginx, and other reverse proxies.

## Features

- **Multiple Authentication Methods**: Password, Header-based (Warden), and Session authentication
- **Priority-based Checker Chain**: Configurable authentication method priority
- **Step-up Authentication**: Support for sensitive path protection with additional authentication
- **Auth Refresh**: Automatic refresh of user authorization information
- **Flexible Header Mapping**: Customizable authentication response headers
- **Framework Agnostic**: Core logic is framework-independent with Fiber adapter included
- **Cross-domain Support**: Cookie utilities for cross-domain authentication flows

## Installation

```bash
go get github.com/soulteary/forwardauth-kit
```

## Quick Start

### Basic Fiber Integration

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/session"
    forwardauth "github.com/soulteary/forwardauth-kit"
)

func main() {
    app := fiber.New()
    store := session.New()

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
    ValidPasswords:  []string{"HASHED_PASSWORD_1", "HASHED_PASSWORD_2"},
}

handler := forwardauth.NewHandler(&config)
```

### Header-based Authentication (Warden Integration)

```go
config := forwardauth.Config{
    HeaderAuthEnabled:   true,
    HeaderAuthUserPhone: "X-User-Phone",
    HeaderAuthUserMail:  "X-User-Mail",
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

```go
config := forwardauth.Config{
    SessionEnabled:   true,
    StepUpEnabled:    true,
    StepUpPaths:      []string{"/admin/*", "/settings/security"},
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
        // Refresh user info periodically
        return getUserFromWarden(phone, mail)
    },
}

handler := forwardauth.NewHandler(&config)
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
    proxy_pass http://auth-service:3000/_auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Uri $request_uri;
}
```

## License

MIT License
