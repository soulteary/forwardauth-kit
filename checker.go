package forwardauth

import (
	"strings"
	"time"
)

// AuthChecker defines the interface for authentication checking.
type AuthChecker interface {
	// Check performs the authentication check and returns the result.
	Check(c Context, sess Session) (*AuthResult, error)
	// Priority returns the priority of this checker (lower = higher priority).
	Priority() int
	// Name returns the name of this checker.
	Name() string
}

// PasswordChecker implements password-based authentication.
type PasswordChecker struct {
	config *Config
}

// NewPasswordChecker creates a new password checker.
func NewPasswordChecker(config *Config) *PasswordChecker {
	return &PasswordChecker{config: config}
}

// Check implements AuthChecker.
func (c *PasswordChecker) Check(ctx Context, sess Session) (*AuthResult, error) {
	password := ctx.Get(c.config.PasswordHeader)
	if password == "" {
		return nil, nil // No password provided, skip this checker
	}

	// Use custom check function if provided
	if c.config.PasswordCheckFunc != nil {
		if c.config.PasswordCheckFunc(password) {
			return &AuthResult{
				Authenticated: true,
				AuthMethod:    AuthMethodPassword,
			}, nil
		}
		return nil, ErrInvalidPassword
	}

	// Normalize password if normalizer provided
	var normalizedPassword string
	if c.config.PasswordNormalizer != nil {
		normalizedPassword = c.config.PasswordNormalizer(password)
	} else {
		// Default normalization: uppercase, trim spaces
		normalizedPassword = strings.ToUpper(strings.TrimSpace(password))
		normalizedPassword = strings.ReplaceAll(normalizedPassword, " ", "")
	}

	// Check against valid passwords
	for _, validPassword := range c.config.ValidPasswords {
		if constantTimeEqual(validPassword, normalizedPassword) {
			return &AuthResult{
				Authenticated: true,
				AuthMethod:    AuthMethodPassword,
			}, nil
		}
	}

	return nil, ErrInvalidPassword
}

// Priority implements AuthChecker.
func (c *PasswordChecker) Priority() int {
	return 10 // High priority
}

// Name implements AuthChecker.
func (c *PasswordChecker) Name() string {
	return "password"
}

// HeaderChecker implements header-based authentication (e.g., Warden).
type HeaderChecker struct {
	config *Config
}

// NewHeaderChecker creates a new header checker.
func NewHeaderChecker(config *Config) *HeaderChecker {
	return &HeaderChecker{config: config}
}

// Check implements AuthChecker.
func (c *HeaderChecker) Check(ctx Context, sess Session) (*AuthResult, error) {
	phone := ctx.Get(c.config.HeaderAuthUserPhone)
	mail := ctx.Get(c.config.HeaderAuthUserMail)

	if phone == "" && mail == "" {
		return nil, nil // No headers provided, skip this checker
	}

	// Check if user exists in allow list
	if c.config.HeaderAuthCheckFunc != nil {
		if c.config.HeaderAuthCheckFunc(phone, mail) {
			result := &AuthResult{
				Authenticated: true,
				Phone:         phone,
				Email:         mail,
				AuthMethod:    AuthMethodHeader,
			}

			// Get full user info if available
			if c.config.HeaderAuthGetInfoFunc != nil {
				userInfo := c.config.HeaderAuthGetInfoFunc(phone, mail)
				if userInfo != nil {
					result.UserID = userInfo.UserID
					result.Email = userInfo.Email
					result.Phone = userInfo.Phone
					result.Name = userInfo.Name
					result.Scopes = userInfo.Scopes
					result.Role = userInfo.Role
				}
			}

			return result, nil
		}
	}

	return nil, ErrUserNotFound
}

// Priority implements AuthChecker.
func (c *HeaderChecker) Priority() int {
	return 20 // Medium priority
}

// Name implements AuthChecker.
func (c *HeaderChecker) Name() string {
	return "header"
}

// SessionChecker implements session-based authentication.
type SessionChecker struct {
	config *Config
}

// NewSessionChecker creates a new session checker.
func NewSessionChecker(config *Config) *SessionChecker {
	return &SessionChecker{config: config}
}

// Check implements AuthChecker.
func (c *SessionChecker) Check(ctx Context, sess Session) (*AuthResult, error) {
	if sess == nil {
		return nil, ErrSessionRequired
	}

	// Check if authenticated
	authVal := sess.Get(KeyAuthenticated)
	if authVal == nil {
		return nil, ErrNotAuthenticated
	}

	authenticated, ok := authVal.(bool)
	if !ok || !authenticated {
		return nil, ErrNotAuthenticated
	}

	// Build result from session data
	result := &AuthResult{
		Authenticated: true,
		AuthMethod:    AuthMethodSession,
	}

	// Get user ID
	if val := sess.Get(KeyUserID); val != nil {
		if id, ok := val.(string); ok {
			result.UserID = id
		}
	}

	// Get email
	if val := sess.Get(KeyUserMail); val != nil {
		if mail, ok := val.(string); ok {
			result.Email = mail
		}
	}

	// Get phone
	if val := sess.Get(KeyUserPhone); val != nil {
		if phone, ok := val.(string); ok {
			result.Phone = phone
		}
	}

	// Get name
	if val := sess.Get(KeyUserName); val != nil {
		if name, ok := val.(string); ok {
			result.Name = name
		}
	}

	// Get scopes
	if val := sess.Get(KeyUserScope); val != nil {
		switch scopes := val.(type) {
		case []string:
			result.Scopes = scopes
		case []interface{}:
			result.Scopes = interfaceSliceToStrings(scopes)
		}
	}

	// Get role
	if val := sess.Get(KeyUserRole); val != nil {
		if role, ok := val.(string); ok {
			result.Role = role
		}
	}

	// Get AMR
	if val := sess.Get(KeyUserAMR); val != nil {
		switch amr := val.(type) {
		case []string:
			result.AMR = amr
		case []interface{}:
			result.AMR = interfaceSliceToStrings(amr)
		}
	}

	// Check if refresh is needed
	if c.config.AuthRefreshEnabled {
		result.NeedsRefresh = c.needsRefresh(sess)
	}

	return result, nil
}

// needsRefresh checks if the session needs an auth refresh.
func (c *SessionChecker) needsRefresh(sess Session) bool {
	lastRefreshVal := sess.Get(KeyAuthRefreshedAt)
	if lastRefreshVal == nil {
		return true
	}

	lastRefreshTime, ok := lastRefreshVal.(int64)
	if !ok {
		return true
	}

	lastRefresh := time.Unix(lastRefreshTime, 0)
	return time.Since(lastRefresh) > c.config.AuthRefreshInterval
}

// Priority implements AuthChecker.
func (c *SessionChecker) Priority() int {
	return 30 // Lower priority than password and header
}

// Name implements AuthChecker.
func (c *SessionChecker) Name() string {
	return "session"
}

// constantTimeEqual compares two strings in constant time to prevent timing attacks.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// interfaceSliceToStrings converts []interface{} to []string.
func interfaceSliceToStrings(slice []interface{}) []string {
	result := make([]string, 0, len(slice))
	for _, v := range slice {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
