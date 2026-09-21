# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Because Go encodes the major version in the import path, every major release
also changes the module path. The current one is
`github.com/soulteary/forwardauth-kit/v3`.

## [Unreleased]

## [3.0.0] — 2026-09-21

### Changed — BREAKING

- **Fiber support moved to the `fiberadapter` subpackage.** The root package no
  longer imports Fiber, so a binary that never serves a Fiber route no longer
  links it — and since Fiber was the root package's only third-party
  dependency, **the root package now depends on nothing outside the standard
  library**.

  Measured against v2.2.0, building the same program (one that calls
  `NewHandler` and reads the config back) with `go build -trimpath`:

  | | v2.2.0 | v3.0.0 |
  |---|---:|---:|
  | linked packages | 279 | 86 |
  | modules in the build list | 31 | 20 |
  | binary size | 8,876,096 B | 3,114,236 B |
  | `// indirect` lines in the consumer's `go.mod` | 16 | 0 |
  | modules in the consumer's `go.sum` | 22 | 2 |

  That is 193 fewer linked packages and a **64.9% smaller binary**. Twenty
  modules leave the consumer's `go.sum` — Fiber itself, fasthttp, gofiber's
  schema and utils, klauspost/compress, tinylib/msgp, philhofer/fwd,
  valyala/bytebufferpool, google/uuid, molecule-man/go-brrr, mattn/go-isatty
  and mattn/go-colorable; five `golang.org/x` modules (crypto, net, sys, text,
  tools); and the three Fiber pulls in for its own tests (fxamacker/cbor,
  shamaton/msgpack, x448/float16).

  A Fiber user pays nothing for the move. The same Fiber program measures 279 →
  280 linked packages and 10,954,085 → 10,957,101 bytes: one package and three
  kilobytes, which is `fiberadapter` itself.

  | Removed from the root package | Replacement |
  |---|---|
  | `forwardauth.FiberContext` | `fiberadapter.Context` |
  | `forwardauth.NewFiberContext` | `fiberadapter.NewContext` |
  | `forwardauth.FiberSession` | `fiberadapter.Session` |
  | `forwardauth.NewFiberSession` | `fiberadapter.NewSession` |
  | `forwardauth.FiberSessionStore` | `fiberadapter.SessionStore` |
  | `forwardauth.NewFiberSessionStore` | `fiberadapter.NewSessionStore` |
  | `forwardauth.FiberMiddleware` | `fiberadapter.Middleware` |
  | `forwardauth.FiberCheckRoute` | `fiberadapter.CheckRoute` |
  | `forwardauth.FiberCookieHelper` | `fiberadapter.CookieHelper` |
  | `forwardauth.NewFiberCookieHelper` | `fiberadapter.NewCookieHelper` |

  Keeping these as deprecated shims was not an option: a shim has to import
  Fiber, which relinks fasthttp and gives back the entire benefit.

  A subpackage is enough; Fiber does not need its own module. Module graph
  pruning keeps a requirement that no imported package needs out of the
  consumer's `go.mod` and `go.sum` entirely — measured above, Fiber appears in
  neither.

  It is not, however, out of the *module graph*. `go list -m all` in a
  root-package-only consumer still names `github.com/gofiber/fiber/v3 v3.5.0`
  and its fifteen runtime dependencies, because MVS still propagates their
  minimum versions. Nothing downloads, hashes or links them, but a consumer
  that later imports Fiber for its own reasons inherits this module's floor.

- **The module path is therefore now `github.com/soulteary/forwardauth-kit/v3`**,
  as Go's import compatibility rule requires of a release that removes exported
  symbols. Every user must update the import path, including net/http users who
  are otherwise unaffected.

- `Underlying()` on the moved wrappers is now `Unwrap()`, the name Go uses
  elsewhere for reaching an inner value.

- Apart from the import path, nothing in the core changed. `Config`, `Handler`,
  the `AuthChecker` implementations, `AuthHeaderBuilder`, `ForwardedHeaders`
  and the response helpers keep their signatures and their behaviour.

### Added

- **The `httpadapter` subpackage: a net/http adapter.** `httpadapter.NewContext`
  implements `forwardauth.Context` over an `http.ResponseWriter` and
  `*http.Request`, and `httpadapter.CheckRoute` is the endpoint. It costs
  nothing to import, being standard library throughout, and it covers Echo, Gin
  and chi as they stand, since all three hand out the same pair.

  `Hostname()` strips the port, matching what Fiber's returns, so a `Config`
  comparing `AuthHost` against the request host behaves the same on either
  adapter. `Protocol()` deliberately does *not* read `X-Forwarded-Proto`:
  whether that header may be believed is one decision, and it already lives in
  `ForwardedHeaders.GetProto`.

- **`Handler.Serve` and `Handler.ServeWithStore`** — the whole endpoint
  (fetch the session, run the checks, answer a failure, emit the headers and
  200 on success) expressed against `Context` and `Session` alone, with no web
  framework in sight. Both adapters are now thin enough to read in one screen,
  and an adapter for a fourth framework has nothing left to decide. The
  sequence used to be written out inside `FiberMiddleware`, where a second
  framework would have meant a second copy of it — two sets of rules about when
  a request counts as authenticated, drifting apart on an authentication
  endpoint.

  A nil store means no session, which is the ordinary shape of a ForwardAuth
  deployment whose sessions live in the authentication service, and of one
  using only password or header authentication. `FiberMiddleware` would have
  panicked.

- **`Handler.HandleCheckError`**, for a caller that runs `Check` itself — to
  inspect the `AuthResult`, or to authorize a route in process — and then wants
  the endpoint's own answer for a failure without re-running the checks.
  `HeaderAuthCheckFunc` and `HeaderAuthGetInfoFunc` are usually directory
  lookups, so running them twice is not free.

- **`SessionStoreFunc`**, adapting a plain function to `SessionStore`. Outside
  Fiber there is no one session library to wrap, so this is the whole
  integration point for gorilla/sessions, scs or a hand-rolled store.

- `fiberadapter.Store` and `fiberadapter.CtxSource`: the small interfaces the
  adapter actually needs, in place of `*session.Store` and a type assertion to
  `*FiberContext`.

  `Store` is what a Fiber session store looks like from here, so a store chosen
  per tenant, one that records metrics, or a test double all work where only
  `*session.Store` did — which is also how `SessionStore.Get`'s store-failure
  path is now tested at all: a real `*session.Store` cannot be asked to fail on
  demand. `CtxSource` is what a `Context` has to offer to reach
  the Fiber request behind it — previously the session store asserted the
  concrete `*FiberContext`, so a caller's own wrapper came back as
  `ErrInvalidConfig` with nothing saying why.

- A package doc in `doc.go` describing the layout, the security rules that
  govern the identity headers, and how to write an adapter for another
  framework.

- Runnable examples (`Example`, `ExampleProxySecretTrustFunc`,
  `ExampleHandler_ServeWithStore`, `ExampleSessionStoreFunc`,
  `ExampleConfig_Validate`, `ExampleAuthResult_authRefreshFailed`) that
  `go test` verifies, so they cannot drift from the API.

- `CHANGELOG.md`.

- `.github/workflows/release.yml`. Eight tags exist with nothing having checked
  any of them, and this repository has already made the one mistake that is
  caught at tag time or not at all: **`v1.4.0` and `v2.0.0` point at the same
  commit**, and that commit's `go.mod` declares `/v2` — so `v1.4.0` is not
  fetchable, and the proxy's v1 list stops at v1.3.0. The gate runs on a `v*`
  tag (and on demand): the module path must carry the tag's major version, with
  v0 and v1 taking no suffix, and both READMEs' `go get` line must name that
  same path. Then the CI gate against the tagged commit — gofmt, `go mod tidy`
  cleanliness, vet, golangci-lint, `go test -race` with coverage, and
  govulncheck. Verification only: it publishes nothing and takes no write
  permissions.

- A `layout` job in CI, and the same check in the release gate: the root
  package and `httpadapter` must import nothing outside the standard library.
  The split is only worth anything while it holds, and one stray import puts a
  third-party module back into every consumer's `go.sum` with nothing else
  noticing.

- `.github/dependabot.yml`. Weekly gomod and github-actions updates, minor and
  patch grouped into one PR, majors left separate — for this module a
  dependency major is a judgement call. The release gate is an action too, so a
  silently stale action would be a stale release check.

### Fixed

- A `Check` error that *wraps* one of the sentinels is now read for what it
  wraps. `FiberMiddleware` compared by identity, so a custom `AuthChecker`
  returning `fmt.Errorf("...: %w", ErrStepUpRequired)` — the ordinary way to
  say which check refused — fell through to the login redirect, which is the
  one answer that cannot resolve a step-up requirement, because the user is
  already authenticated.

### Changed

- Dependencies: `gofiber/schema` 1.8.6 → 1.8.7, `gofiber/utils/v2` 2.5.1 →
  2.5.2, `molecule-man/go-brrr` 1.1.0 → 1.1.1. All indirect, all patch
  releases. `gofiber/fiber/v3` stays at v3.5.0 and `stretchr/testify` at
  v1.12.1, both already current.

## [2.2.0] — 2026-09-12

- Step-up now matches the *forwarded* URI rather than this endpoint's own path,
  which is why `StepUpPaths` used to match nothing.
- An authorization refresh replaces scopes and role rather than merging them,
  so a revocation takes effect; a failed lookup clears them and sets
  `AuthResult.AuthRefreshFailed`.
- `ErrHeaderAuthTrustUnspecified`: header authentication now requires an
  explicit trust decision.
- Emitted headers drop comma-containing scope and AMR values, and values
  carrying CR, LF or NUL.

## [2.0.0] — 2026-09-11

- Fiber v3. Applications still on Fiber v2 should stay on
  `github.com/soulteary/forwardauth-kit` v1.

[Unreleased]: https://github.com/soulteary/forwardauth-kit/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/soulteary/forwardauth-kit/compare/v2.2.0...v3.0.0
[2.2.0]: https://github.com/soulteary/forwardauth-kit/compare/v2.1.0...v2.2.0
[2.0.0]: https://github.com/soulteary/forwardauth-kit/compare/v1.3.0...v2.0.0
