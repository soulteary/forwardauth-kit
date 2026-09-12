package forwardauth

import "errors"

// Error definitions for ForwardAuth.
var (
	// Configuration errors
	ErrNoPasswordConfigured = errors.New("password authentication enabled but no passwords configured")
	// ErrHeaderAuthTrustUnspecified indicates header-based authentication is
	// enabled without stating whether the identity headers can be trusted.
	// Set HeaderAuthTrustFunc to say which requests may supply them, or
	// HeaderAuthAllowUntrustedHeaders to accept them from any caller.
	//
	// Neither replaces the proxy stripping the client's identity headers and
	// setting its own. What a trust check does and does not establish is
	// documented on HeaderAuthTrustFunc and stated only there -- paraphrasing
	// it here is what left this comment recommending a peer check, which is
	// the one check the rule exists to rule out.
	ErrHeaderAuthTrustUnspecified = errors.New("header auth requires HeaderAuthTrustFunc or HeaderAuthAllowUntrustedHeaders")

	ErrNoUserCheckFunc = errors.New("header authentication enabled but no user check function provided")
	ErrInvalidConfig   = errors.New("invalid configuration")

	// Authentication errors
	ErrNotAuthenticated  = errors.New("not authenticated")
	ErrInvalidPassword   = errors.New("invalid password")
	ErrUserNotFound      = errors.New("user not found")
	ErrSessionRequired   = errors.New("session required")
	ErrStepUpRequired    = errors.New("step-up authentication required")
	ErrSessionStoreError = errors.New("session store error")

	// HTTP status related
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// ErrorCode represents an error code for API responses.
type ErrorCode string

const (
	ErrorCodeUnauthorized    ErrorCode = "unauthorized"
	ErrorCodeInvalidPassword ErrorCode = "invalid_password"
	ErrorCodeUserNotFound    ErrorCode = "user_not_found"
	ErrorCodeSessionRequired ErrorCode = "session_required"
	ErrorCodeStepUpRequired  ErrorCode = "step_up_required"
	ErrorCodeSessionError    ErrorCode = "session_error"
	ErrorCodeInternalError   ErrorCode = "internal_error"
)

// ErrorResponse represents an error response structure.
type ErrorResponse struct {
	OK      bool      `json:"ok"`
	Code    ErrorCode `json:"code,omitempty"`
	Message string    `json:"message,omitempty"`
	Status  int       `json:"status,omitempty"`
}

// NewErrorResponse creates a new error response.
func NewErrorResponse(code ErrorCode, message string, status int) *ErrorResponse {
	return &ErrorResponse{
		OK:      false,
		Code:    code,
		Message: message,
		Status:  status,
	}
}
