# forwardauth-kit

ForwardAuth 中间件库，用于反向代理认证。支持多种认证方式，与会话管理集成，适用于 Traefik、Nginx 等反向代理。

## 特性

- **多种认证方式**：密码、Header（Warden）、Session 认证
- **优先级检查链**：可配置认证方式优先级
- **Step-up 认证**：敏感路径二次认证保护
- **授权刷新**：自动刷新用户授权信息
- **灵活的 Header 映射**：可自定义认证响应头
- **框架无关**：核心逻辑框架无关，内置 Fiber 适配器
- **跨域支持**：跨域认证流程的 Cookie 工具

## 安装

```bash
go get github.com/soulteary/forwardauth-kit
```

## 快速开始

### Fiber 基础集成

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

    // 配置 ForwardAuth
    config := forwardauth.Config{
        SessionEnabled: true,
        AuthHost:       "auth.example.com",
        LoginPath:      "/_login",
    }

    handler := forwardauth.NewHandler(&config)

    // 注册 ForwardAuth 检查路由
    app.All("/_auth", forwardauth.FiberCheckRoute(handler, store))

    app.Listen(":3000")
}
```

### 密码认证

```go
config := forwardauth.Config{
    PasswordEnabled: true,
    PasswordHeader:  "Stargate-Password",
    ValidPasswords:  []string{"HASHED_PASSWORD_1", "HASHED_PASSWORD_2"},
}

handler := forwardauth.NewHandler(&config)
```

### Header 认证（Warden 集成）

```go
config := forwardauth.Config{
    HeaderAuthEnabled:   true,
    HeaderAuthUserPhone: "X-User-Phone",
    HeaderAuthUserMail:  "X-User-Mail",
    HeaderAuthCheckFunc: func(phone, mail string) bool {
        // 检查用户是否在白名单中
        return wardenClient.CheckUserInList(phone, mail)
    },
    HeaderAuthGetInfoFunc: func(phone, mail string) *forwardauth.UserInfo {
        // 获取完整用户信息用于设置 Header
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

### Step-up 认证

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

### 授权信息刷新

```go
config := forwardauth.Config{
    SessionEnabled:      true,
    HeaderAuthEnabled:   true,
    AuthRefreshEnabled:  true,
    AuthRefreshInterval: 5 * time.Minute,
    HeaderAuthGetInfoFunc: func(phone, mail string) *forwardauth.UserInfo {
        // 定期刷新用户信息
        return getUserFromWarden(phone, mail)
    },
}

handler := forwardauth.NewHandler(&config)
```

## 配置项

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `SessionEnabled` | bool | true | 启用 Session 认证 |
| `PasswordEnabled` | bool | false | 启用密码 Header 认证 |
| `PasswordHeader` | string | "Stargate-Password" | 密码 Header 名称 |
| `ValidPasswords` | []string | - | 有效密码哈希列表 |
| `PasswordCheckFunc` | func | - | 自定义密码验证函数 |
| `HeaderAuthEnabled` | bool | false | 启用 Header 认证 |
| `HeaderAuthUserPhone` | string | "X-User-Phone" | 手机号 Header 名称 |
| `HeaderAuthUserMail` | string | "X-User-Mail" | 邮箱 Header 名称 |
| `HeaderAuthCheckFunc` | func | - | 用户存在性检查函数 |
| `HeaderAuthGetInfoFunc` | func | - | 用户信息获取函数 |
| `StepUpEnabled` | bool | false | 启用 Step-up 认证 |
| `StepUpPaths` | []string | - | 受保护路径 Glob 模式 |
| `StepUpURL` | string | "/_step_up" | Step-up 验证 URL |
| `StepUpSessionKey` | string | "step_up_verified" | Step-up 标志 Session 键 |
| `AuthRefreshEnabled` | bool | false | 启用授权刷新 |
| `AuthRefreshInterval` | Duration | 5m | 刷新间隔 |
| `UserHeaderName` | string | "X-Forwarded-User" | 主用户 Header |
| `AuthUserHeader` | string | "X-Auth-User" | 用户 ID Header |
| `AuthEmailHeader` | string | "X-Auth-Email" | 邮箱 Header |
| `AuthScopesHeader` | string | "X-Auth-Scopes" | Scopes Header（逗号分隔） |
| `AuthRoleHeader` | string | "X-Auth-Role" | 角色 Header |
| `AuthAMRHeader` | string | "X-Auth-AMR" | AMR Header（逗号分隔） |
| `AuthHost` | string | - | 认证服务主机 |
| `LoginPath` | string | "/_login" | 登录页路径 |
| `CallbackParam` | string | "callback" | 回调查询参数 |

## 响应 Header

认证成功时设置以下 Header：

| Header | 说明 | 示例 |
|--------|------|------|
| `X-Forwarded-User` | 用户标识或 "authenticated" | `user-123` |
| `X-Auth-User` | 用户 ID | `user-123` |
| `X-Auth-Email` | 用户邮箱 | `user@example.com` |
| `X-Auth-Scopes` | 逗号分隔的权限范围 | `read,write,admin` |
| `X-Auth-Role` | 用户角色 | `admin` |
| `X-Auth-AMR` | 使用的认证方法 | `otp,mfa` |

## 自定义检查器

实现 `AuthChecker` 接口添加自定义认证方式：

```go
type CustomChecker struct {
    config *forwardauth.Config
}

func (c *CustomChecker) Check(ctx forwardauth.Context, sess forwardauth.Session) (*forwardauth.AuthResult, error) {
    // 自定义认证逻辑
    token := ctx.Get("Authorization")
    if token == "" {
        return nil, nil // 跳到下一个检查器
    }

    // 验证 token...
    if valid {
        return &forwardauth.AuthResult{
            Authenticated: true,
            UserID:        "user-123",
            AuthMethod:    forwardauth.AuthMethodToken,
        }, nil
    }
    return nil, forwardauth.ErrNotAuthenticated
}

func (c *CustomChecker) Priority() int { return 5 } // 优先级高于密码(10)
func (c *CustomChecker) Name() string { return "custom" }

// 添加到 handler
handler.AddChecker(&CustomChecker{config: &config})
```

## Traefik 配置

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

## Nginx 配置

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

## 许可证

MIT License
