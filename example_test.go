package forwardauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	forwardauth "github.com/soulteary/forwardauth-kit/v3"
	"github.com/soulteary/forwardauth-kit/v3/httpadapter"
)

// The common case: a ForwardAuth endpoint a proxy calls before every request,
// answering 200 plus the identity headers, or 401.
func Example() {
	config := &forwardauth.Config{
		HeaderAuthEnabled: true,
		// The identity headers are a claim, not a credential. This says which
		// requests may carry them; the proxy must still overwrite whatever the
		// client sent. See ProxySecretTrustFunc.
		HeaderAuthTrustFunc: forwardauth.ProxySecretTrustFunc("X-Proxy-Secret", "shared-secret"),
		HeaderAuthCheckFunc: func(_, mail string) bool {
			return mail == "user@example.com"
		},
		HeaderAuthGetInfoFunc: func(_, mail string) *forwardauth.UserInfo {
			return &forwardauth.UserInfo{UserID: "u-1", Email: mail, Role: "admin"}
		},
	}
	if err := config.Validate(); err != nil {
		fmt.Println(err)
		return
	}

	endpoint := httpadapter.CheckRoute(forwardauth.NewHandler(config), nil)

	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	req.Header.Set("X-Proxy-Secret", "shared-secret")
	req.Header.Set("X-User-Mail", "user@example.com")
	rec := httptest.NewRecorder()
	endpoint(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Header().Get("X-Forwarded-User"))
	fmt.Println(rec.Header().Get("X-Auth-Role"))

	// Output:
	// 200
	// u-1
	// admin
}

// A request that did not come through the proxy carries no secret, so the
// identity headers on it are not believed -- however well-formed they are.
func ExampleProxySecretTrustFunc() {
	config := &forwardauth.Config{
		HeaderAuthEnabled:   true,
		HeaderAuthTrustFunc: forwardauth.ProxySecretTrustFunc("X-Proxy-Secret", "shared-secret"),
		HeaderAuthCheckFunc: func(_, mail string) bool { return mail == "user@example.com" },
	}
	endpoint := httpadapter.CheckRoute(forwardauth.NewHandler(config), nil)

	forged := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	forged.Header.Set("X-User-Mail", "user@example.com")
	forged.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	endpoint(rec, forged)

	fmt.Println(rec.Code)
	fmt.Print(rec.Body.String())

	// Output:
	// 401
	// {"code":401,"error":"authentication required"}
}

// An unauthenticated browser is sent to the login page rather than given a
// 401, with the origin it was trying to reach passed back as the callback. The
// origin comes from the forwarded headers, because the proxy calls this
// endpoint at its own fixed URL.
func ExampleHandler_ServeWithStore() {
	config := &forwardauth.Config{
		SessionEnabled: true,
		AuthHost:       "auth.example.com",
	}
	endpoint := httpadapter.CheckRoute(forwardauth.NewHandler(config), nil)

	req := httptest.NewRequest(http.MethodGet, "/_auth", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	endpoint(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Header().Get("Location"))

	// Output:
	// 302
	// https://auth.example.com/_login?callback=app.example.com
}

// Outside Fiber there is no session library to adapt, so SessionStoreFunc is
// the whole integration point: return anything satisfying forwardauth.Session.
func ExampleSessionStoreFunc() {
	store := forwardauth.SessionStoreFunc(func(forwardauth.Context) (forwardauth.Session, error) {
		return &exampleSession{data: map[string]interface{}{
			forwardauth.KeyAuthenticated: true,
			forwardauth.KeyUserID:        "u-1",
			forwardauth.KeyUserScope:     []string{"read", "write"},
		}}, nil
	})

	handler := forwardauth.NewHandler(&forwardauth.Config{SessionEnabled: true})

	rec := httptest.NewRecorder()
	httpadapter.CheckRoute(handler, store)(rec, httptest.NewRequest(http.MethodGet, "/_auth", nil))

	fmt.Println(rec.Code)
	fmt.Println(rec.Header().Get("X-Auth-User"))
	fmt.Println(rec.Header().Get("X-Auth-Scopes"))

	// Output:
	// 200
	// u-1
	// read,write
}

// Validate is what turns a missing decision into a boot failure. NewHandler
// does not call it, so a configuration that never says whether the identity
// headers can be trusted builds a Handler that refuses every request at
// runtime instead.
func ExampleConfig_Validate() {
	config := &forwardauth.Config{
		HeaderAuthEnabled:   true,
		HeaderAuthCheckFunc: func(_, _ string) bool { return true },
	}

	fmt.Println(config.Validate())

	config.HeaderAuthTrustFunc = forwardauth.ProxySecretTrustFunc("X-Proxy-Secret", "shared-secret")
	fmt.Println(config.Validate())

	// Output:
	// header auth requires HeaderAuthTrustFunc or HeaderAuthAllowUntrustedHeaders
	// <nil>
}

// A refresh that cannot reach the directory drops the session's cached
// authorization rather than leaving it in place, and says so in
// AuthRefreshFailed -- which is how a caller that would rather fail the
// request than serve it unprivileged can tell.
func ExampleAuthResult_authRefreshFailed() {
	handler := forwardauth.NewHandler(&forwardauth.Config{
		SessionEnabled:      true,
		AuthRefreshEnabled:  true,
		AuthRefreshInterval: 0,
		HeaderAuthGetInfoFunc: func(_, _ string) *forwardauth.UserInfo {
			return nil // user gone, or the directory is unreachable
		},
	})

	sess := &exampleSession{data: map[string]interface{}{
		forwardauth.KeyAuthenticated: true,
		forwardauth.KeyUserID:        "u-1",
		forwardauth.KeyUserMail:      "user@example.com",
		forwardauth.KeyUserRole:      "admin",
		forwardauth.KeyUserScope:     []string{"read", "write"},
	}}

	c := httpadapter.NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_auth", nil))
	result, err := handler.Check(c, sess)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(result.AuthRefreshFailed)
	fmt.Printf("%q %v\n", result.Role, result.Scopes)

	// Output:
	// true
	// "" []
}

// exampleSession is the map-backed session these examples use in place of a
// real store.
type exampleSession struct {
	data map[string]interface{}
}

func (s *exampleSession) Get(key string) interface{}    { return s.data[key] }
func (s *exampleSession) Set(key string, v interface{}) { s.data[key] = v }
func (s *exampleSession) Delete(key string)             { delete(s.data, key) }
func (s *exampleSession) Save() error                   { return nil }
func (s *exampleSession) Destroy() error                { clear(s.data); return nil }
func (s *exampleSession) ID() string                    { return "example-session" }
