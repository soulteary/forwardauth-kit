// Package forwardauth provides ForwardAuth middleware for reverse proxy
// authentication. It supports multiple authentication methods and integrates
// with session management for use with Traefik, Nginx, and other reverse
// proxies supporting ForwardAuth.
//
// # Layout
//
// The root package depends on nothing outside the standard library. It holds
// the whole decision -- the [Config], the [AuthChecker] implementations that
// read a request, the [Handler] that runs them in priority order, and the
// [AuthHeaderBuilder] that turns the result into headers for the proxy to pass
// downstream -- expressed against the [Context] and [Session] abstractions
// rather than any web framework.
//
// Each framework lives in a subpackage, so importing the root package never
// links a framework the service does not use:
//
//   - github.com/soulteary/forwardauth-kit/v3/fiberadapter -- Fiber v3, and
//     with it fasthttp.
//   - github.com/soulteary/forwardauth-kit/v3/httpadapter -- net/http, and
//     with it nothing at all.
//
// A net/http service pays nothing for Fiber support existing; only importing
// fiberadapter links it in.
//
// # Getting started
//
//	config := &forwardauth.Config{
//		SessionEnabled: true,
//		AuthHost:       "auth.example.com",
//	}
//	if err := config.Validate(); err != nil {
//		log.Fatal(err)
//	}
//	handler := forwardauth.NewHandler(config)
//
//	mux.Handle("/_auth", httpadapter.CheckRoute(handler, nil))
//
// Call [Config.Validate] at startup. [NewHandler] does not, so a configuration
// that enables header authentication without declaring whether the identity
// headers can be trusted builds a Handler that refuses every such request at
// runtime rather than failing the process at boot.
//
// The endpoint answers 200 with the authentication headers on a successful
// check, and either a redirect to the login page or an error response on a
// failed one, chosen by the request's Accept header. See [SendErrorResponse]
// and [GetPreferredFormat].
//
// # Security
//
// The identity headers read by header authentication are a claim, not a
// credential: anything that can reach this endpoint can set them. They are
// safe only when the proxy in front strips whatever the client sent and
// replaces it with a value it established itself. [Config.HeaderAuthTrustFunc]
// and [ProxySecretTrustFunc] sit on top of that; they establish that a request
// came THROUGH the proxy, which says nothing about who wrote the headers it
// carries. The same applies to X-Forwarded-Uri and step-up matching -- see
// [Config.StepUpForwardedURITrusted].
//
// # Writing an adapter for another framework
//
// The whole endpoint is [Handler.ServeWithStore], which knows about no web
// framework. An adapter implements [Context] over the framework's request type
// and calls it; that is all httpadapter is, and all fiberadapter is beyond the
// Fiber session store it wraps.
//
// Nothing about when a request counts as authenticated belongs in an adapter.
// A second copy of that sequence is a second set of rules, and the two drift --
// which on an authentication endpoint means one framework admitting a request
// the other refuses.
package forwardauth
