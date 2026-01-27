package forwardauth

import (
	"context"
	"time"
)

// Context abstracts the HTTP context interface for framework independence.
type Context interface {
	// Request information
	Path() string
	Method() string
	Protocol() string
	Hostname() string
	Get(key string) string // Get request header
	Query(key string) string

	// Response methods
	Set(key, value string) // Set response header
	SendStatus(status int) error
	Redirect(location string, status ...int) error
	Status(status int) Context
	JSON(v interface{}) error
	SendString(s string) error

	// Session/Locals
	Locals(key string, value ...interface{}) interface{}

	// Context
	Context() context.Context
}

// Session abstracts the session interface.
type Session interface {
	Get(key string) interface{}
	Set(key string, value interface{})
	Delete(key string)
	Save() error
	Destroy() error
	ID() string
}

// SessionStore abstracts the session store interface.
type SessionStore interface {
	Get(c Context) (Session, error)
}

// AuthResult contains the result of an authentication check.
type AuthResult struct {
	Authenticated bool
	UserID        string
	Email         string
	Phone         string
	Scopes        []string
	Role          string
	AMR           []string // Authentication Methods Reference
	AuthMethod    AuthMethod
	NeedsRefresh  bool
	RefreshedAt   time.Time
}

// AuthMethod represents the authentication method used.
type AuthMethod int

const (
	AuthMethodNone AuthMethod = iota
	AuthMethodSession
	AuthMethodPassword
	AuthMethodHeader
	AuthMethodToken
)

// String returns the string representation of the auth method.
func (m AuthMethod) String() string {
	switch m {
	case AuthMethodSession:
		return "session"
	case AuthMethodPassword:
		return "password"
	case AuthMethodHeader:
		return "header"
	case AuthMethodToken:
		return "token"
	default:
		return "none"
	}
}

// UserInfo contains user information from an external source.
type UserInfo struct {
	UserID   string
	Email    string
	Phone    string
	Scopes   []string
	Role     string
	Status   string
	Metadata map[string]interface{}
}

// IsActive returns whether the user is active.
func (u *UserInfo) IsActive() bool {
	return u.Status == "" || u.Status == "active"
}

// SessionKeys defines common session key names used by ForwardAuth.
const (
	KeyAuthenticated   = "authenticated"
	KeyUserID          = "user_id"
	KeyUserMail        = "user_mail"
	KeyUserPhone       = "user_phone"
	KeyUserScope       = "user_scope"
	KeyUserRole        = "user_role"
	KeyUserAMR         = "user_amr"
	KeyStepUpVerified  = "step_up_verified"
	KeyAuthRefreshedAt = "auth_refreshed_at"
)
