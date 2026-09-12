# forwardauth-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/forwardauth-kit/v2.svg)](https://pkg.go.dev/github.com/soulteary/forwardauth-kit/v2)
[![Go Report Card](.github/goreportcard.svg)](.github/goreportcard-report.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/forwardauth-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/forwardauth-kit)

[English](README.md)

ForwardAuth 中间件库，用于反向代理认证。支持多种认证方式，与会话管理集成，适用于 Traefik、Nginx 等反向代理。

## 特性

- **多种认证方式**：密码、Header（Warden）、Session 认证
- **优先级检查链**：可配置认证方式优先级
- **Step-up 认证**：敏感路径二次认证保护
- **授权刷新**：自动刷新用户授权信息
- **灵活的 Header 映射**：可自定义认证响应头
- **框架无关**：核心逻辑框架无关，内置 Fiber 适配器
- **跨域支持**：跨域认证流程的 Cookie 工具

## 环境要求

- **Go 1.27+**（`go.mod` 声明 `go 1.27.0`）
- `Fiber*` 适配器需要 Fiber v3.4.0 或更高版本；核心逻辑与框架无关

## 安装

```bash
go get github.com/soulteary/forwardauth-kit/v2
```

Fiber 集成要求 Fiber v3.4.0 或更高版本。仍使用 Fiber v2 的应用应继续使用 `github.com/soulteary/forwardauth-kit` v1。

## 快速开始

### Fiber 基础集成

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
    // 这里放的是明文，以常量时间比较。它们不是哈希。
    // 必须按下面说的归一化规则预先处理好，否则永远匹配不上。
    ValidPasswords: []string{"ACCESSCODE1", "ACCESSCODE2"},
}

handler := forwardauth.NewHandler(&config)
```

**默认归一化会转大写并去掉空格**，这让比较变成大小写不敏感，丢掉了你可能以为还在的
熵。它的形状是为邀请码/访问码（`"ABCD 1234"`）设计的，不是为密码。真正的密码请自己
提供归一化函数：

```go
config.PasswordNormalizer = strings.TrimSpace // 或 nil 表示不做归一化
```

要对哈希校验而不是比对明文列表，请用 `PasswordCheckFunc`：

```go
config := forwardauth.Config{
    PasswordEnabled: true,
    PasswordCheckFunc: func(password string) bool {
        return bcrypt.CompareHashAndPassword(stored, []byte(password)) == nil
    },
}
```

当 `PasswordEnabled` 为真而 `ValidPasswords` 与 `PasswordCheckFunc` 都没设置时，
`Config.Validate()` 会报错。

### Header 认证（Warden 集成）

```go
config := forwardauth.Config{
    HeaderAuthEnabled:   true,
    HeaderAuthUserPhone: "X-User-Phone",
    HeaderAuthUserMail:  "X-User-Mail",

    // 必填。身份 Header 只是"声明"而非凭证：任何能访问到本接口的调用方都能设置它们。
    // 需要明确指定哪些请求可以信任。
    //
    // 应当校验"只有代理才能产生"的东西，例如代理注入的共享密钥；
    // 仅凭网络对端地址是不够的：请求由代理转发，并不能说明 X-User-Phone
    // 是谁写的——除非代理被显式配置为清除它。下方 nginx 示例两件事都做了。
    // proxySecret 为空时不信任任何请求，未携带该 Header 的请求同样不信任。
    // 请不要自己手写这个比较：subtle.ConstantTimeCompare("", "") 返回 1，
    // 密钥没配上时会变成「信任所有请求」，无论有没有带 Header。
    HeaderAuthTrustFunc: forwardauth.ProxySecretTrustFunc("X-Proxy-Secret", proxySecret),
    // ……或显式声明接受任意来源的 Header。仅当代理会「清除」客户端发来的身份
    // Header 并写入自己的值时才安全；能否访问到本接口是另一个问题，回答不了
    // 这一个。只做转发的代理（Traefik 的 trustForwardHeader，或任何没有清除该
    // Header 的 proxy_pass）会把客户端发来的值原样带上，因此即使本接口除代理
    // 外无人可达，客户端依然能把自己伪造成白名单里的任意用户：
    //   HeaderAuthAllowUntrustedHeaders: true,

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

Step-up 用 `StepUpPaths` 匹配的是**原始请求目标**——ForwardAuth 代理通过
`X-Forwarded-Uri` 传过来的那个——而不是认证端点自己的路径。没有转发 URI 时回退到
`Context.Path()`，因此直接（非代理）使用的行为不变。

```go
config := forwardauth.Config{
    SessionEnabled:   true,
    StepUpEnabled:    true,
    StepUpPaths:      []string{"/admin/*", "/settings/security"},
    // 当代理会传递 X-Forwarded-Uri 时必填。二次验证匹配的是"原始目标路径"，
    // 它来自该 Header；只有当代理会"覆盖"它时才可设为 true
    // （nginx 的 `proxy_set_header X-Forwarded-Uri $request_uri` 即是）。
    // 若代理只是原样转发客户端提供的值（如 Traefik 的 trustForwardHeader: true），
    // 客户端就能发送 "X-Forwarded-Uri: /public" 绕过二次验证；
    // 因此该项为 false 时，任何携带此 Header 的请求都会被当作受保护路由。
    // 另外，无论该项取值如何，只要请求没有可用的转发路径（Header 缺失、
    // 为空，或只有查询串），都会被当作受保护路由：此时没有可匹配的目标，
    // 而认证端点自身的路径并不是目标。
    StepUpForwardedURITrusted: true,
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
        // 返回 nil 表示查询失败，或账号已不存在。
        return getUserFromWarden(phone, mail)
    },
}

handler := forwardauth.NewHandler(&config)
```

刷新会**替换**缓存的 scopes 和 role，而不是合并进去，因此把用户的 scopes 撤销为空、
或清掉 role，都能真正生效。当 `HeaderAuthGetInfoFunc` 返回 `nil` 时，缓存的 scopes
和 role 会被清除，并置上 `AuthResult.AuthRefreshFailed`——如果目录服务故障不应让一个
已删除或已停用的账号继续有权限，就检查这个字段并拒绝请求：

```go
result, err := handler.Check(c, sess)
if err != nil {
    return err
}
if result.AuthRefreshFailed {
    // 目录服务无法确认这个用户。失败即关闭。
    return forwardauth.SendErrorResponse(c, http.StatusForbidden, "authorization unavailable")
}
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
| `HeaderAuthTrustFunc` | func(Context) bool | nil | 哪些请求可以提供身份 Header；未设置 `HeaderAuthAllowUntrustedHeaders` 时必填。它是「代理清除这些 Header」之上的一层，而不是替代——它证明的是请求从哪里来，不是这些 Header 由谁写入 |
| `HeaderAuthAllowUntrustedHeaders` | bool | false | 接受任意来源的身份 Header。仅当代理会清除客户端发来的值并写入自己的值时才安全——接口即使完全隔离，只要代理只做转发就仍可被伪造 |
| `StepUpEnabled` | bool | false | 启用 Step-up 认证 |
| `StepUpPaths` | []string | - | 受保护路径 Glob 模式 |
| `StepUpURL` | string | "/_step_up" | Step-up 验证 URL |
| `StepUpSessionKey` | string | "step_up_verified" | Step-up 标志 Session 键 |
| `StepUpForwardedURITrusted` | bool | false | 代理会覆盖 `X-Forwarded-Uri`；为 false 时，任何携带该 Header 的请求都按受保护处理。没有可用转发路径的请求在两种取值下都按受保护处理 |
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

输出的 header 值经过净化：CR 和 LF 会被剥掉，含逗号的 scope 或 AMR 值会被丢弃而不是
输出——`X-Auth-Scopes` 是逗号分隔的，像 `read,admin` 这样的 scope 否则会在下游凭空
多出一项权限。读回 header 请用 `ParseScopesFromHeader`。

## 认证结果

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
    AuthRefreshFailed bool // 目录查询失败，应失败即关闭
}
```

Scope 辅助函数：

```go
forwardauth.ScopesContain(result.Scopes, "admin")
forwardauth.MergeScopesUnique(a, b)
forwardauth.ParseScopesFromHeader("read,write,admin")
```

## 错误

| 哨兵错误 | 含义 |
|----------|------|
| `ErrHeaderAuthTrustUnspecified` | 设置了 `HeaderAuthEnabled`，但既没给 `HeaderAuthTrustFunc` 也没给 `HeaderAuthAllowUntrustedHeaders`。由 `Config.Validate()` 返回——这个决定无法安全地取默认值。 |
| `ErrInvalidConfig` | 配置不可用 |
| `ErrNotAuthenticated` | 没有任何检查器通过认证 |
| `ErrInvalidPassword` | 密码检查器拒绝了该值 |
| `ErrForbidden` | 已认证但无权限 |

请在启动时调用 `Config.Validate()`，这样缺失信任决定会让进程启动失败，而不是默默地
信任客户端提供的身份 header。

## 响应格式辅助函数

```go
forwardauth.IsJSONRequest(c)
forwardauth.IsXMLRequest(c)
forwardauth.IsHTMLRequest(c)
forwardauth.GetPreferredFormat(c)          // "json" | "xml" | "html"
forwardauth.SendErrorResponse(c, 403, msg) // message 会按所选格式转义
forwardauth.NormalizeHost("[::1]:8080")    // "[::1]"
```

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

    # 定义这个密钥。部署时用模板注入（envsubst / Ansible / Helm value 等）——
    # $proxy_secret 不是 nginx 内置变量，只引用不定义会导致 nginx 启动失败。
    set $proxy_secret "REPLACE_WITH_A_LONG_RANDOM_STRING";

    proxy_pass http://auth-service:3000/_auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Uri $request_uri;

    # HeaderAuthTrustFunc 校验的密钥。不要放在面向客户端的 location 中，
    # 否则客户端自己就能发送它。
    proxy_set_header X-Proxy-Secret $proxy_secret;

    # 必须清除身份 Header。否则客户端可以自带 X-User-Phone / X-User-Mail，
    # nginx 原样转发，信任校验随之通过——而这个身份是客户端伪造的。
    # 请用你自己确定的值覆盖它们，或者置空。
    proxy_set_header X-User-Phone "";
    proxy_set_header X-User-Mail "";
}
```

`X-Forwarded-For` 同样由客户端可控：nginx 是在已有值后面追加，前面的条目
都是客户端自己填的。需要对端地址时请使用 `$remote_addr` 而非该 Header；
另外 `forwardauth.Context` 并不暴露对端地址，这类校验需要在进入 handler
之前、在你的适配层完成。

## 升级说明（v2.2.0）

**本次发布可能故意让你的服务启动失败。** 当设置了 `HeaderAuthEnabled` 时，
`Config.Validate()` 现在会返回 `ErrHeaderAuthTrustUnspecified`，除非你提供
`HeaderAuthTrustFunc` 或 `HeaderAuthAllowUntrustedHeaders` 之一。

- **身份 header 现在必须显式做信任决定。** 只要值在允许列表里，`HeaderChecker`
  就会基于 `X-User-Phone` / `X-User-Mail` 完成认证，而且优先级高于 session
  检查器——任何能访问到这个端点的东西都能设置这些 header。README 旧的 nginx 示例
  和 Traefik 的 `trustForwardHeader` 都不会剥掉客户端自己发来的自定义 header。
  本库无法知道你的可信代理是谁，所以这个决定得由你说出来：
  `ProxySecretTrustFunc("X-Proxy-Secret", secret)` 校验只有代理才能产生的东西，
  或者 `HeaderAuthAllowUntrustedHeaders: true` 明确承认任何调用方都可以提供它们。
  **同时请更新你的 nginx/Traefik 配置**——示例现在会清空身份 header 并注入密钥。
- **Step-up 认证现在真的会触发。** 此前模式是拿 `Context.Path()` 来匹配的，而在
  ForwardAuth 部署里它是固定的认证端点（`/_auth`），于是 `StepUpPaths` 什么都匹配不
  到，每条受保护路径上的 step-up 都静默失效。现在改用转发 URI 匹配。**如果你原本
  设置了 `StepUpEnabled`，step-up 会开始挑战此前被放过的请求。** 只有当你的代理会
  *覆写* `X-Forwarded-Uri` 时才设置 `StepUpForwardedURITrusted: true`；为 false 时，
  任何带该 header 的请求都被视为受保护。
- **授权刷新现在能降权。** 它此前是合并而非替换，所以把 scopes 撤销为空、或清掉
  role，旧值会在 session 的整个生命周期里留着。查询失败时只打了日志，于是一个已删除
  的账号在查询持续失败期间一直保有权限。现在刷新会替换，返回 `nil` 则清除缓存的
  scopes 和 role，并置上新增的 `AuthResult.AuthRefreshFailed`。
- **含逗号的 scope 不再凭空多出权限。** `BuildHeaders` 用 `,` 连接 scopes 和 AMR，
  而 `ParseScopesFromHeader` 按它切分。现在这类值会被丢弃，并且每个输出的 header
  值都会剥掉 CR/LF。
- **转义修复。** step-up 重定向把回调 URL（它包含 `://` 和自己的查询串）未转义地
  插进了一个查询参数；`SendErrorResponse` 把 message 未转义地插进了 XML 标记。
- **`NormalizeHost` 能处理 IPv6。** 它此前用 `strings.Index(host, ":")`，会把
  `[::1]:8080` 截断成 `[`。现在改用 `net.SplitHostPort`。
- **`ValidPasswords` 被明确写成明文**——它一直都是明文，尽管字段注释和 README 示例
  把这些值称作哈希。默认密码归一化会转大写，使比较变成大小写不敏感；真正的密码请提供
  `PasswordNormalizer`。

## 测试

```bash
go test ./...

# 带覆盖率
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -func=coverage.out
```

## 许可证

Apache License 2.0 —— 详见 [LICENSE](LICENSE)。
