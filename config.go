// Package forwardauth provides ForwardAuth middleware for reverse proxy authentication.
// It supports multiple authentication methods and integrates with session management
// for use with Traefik, Nginx, and other reverse proxies supporting ForwardAuth.
package forwardauth

import (
	"regexp"
	"strings"
	"time"
)

// Config defines the ForwardAuth handler configuration.
type Config struct {
	// Session configuration
	SessionEnabled bool

	// Password authentication
	PasswordEnabled    bool
	PasswordHeader     string   // Header name for password authentication (default: "Stargate-Password")
	ValidPasswords     []string // List of valid password hashes
	PasswordAlgorithm  string   // Algorithm: "plaintext", "bcrypt", "argon2"
	PasswordCheckFunc  PasswordCheckFunc
	PasswordNormalizer func(password string) string // Optional password normalizer

	// Header-based authentication (e.g., Warden)
	HeaderAuthEnabled     bool
	HeaderAuthUserPhone   string // Header name for phone (default: "X-User-Phone")
	HeaderAuthUserMail    string // Header name for email (default: "X-User-Mail")
	HeaderAuthCheckFunc   UserCheckFunc
	HeaderAuthGetInfoFunc UserInfoFunc

	// Step-up authentication
	StepUpEnabled    bool
	StepUpPaths      []string // Glob patterns for paths requiring step-up auth
	StepUpURL        string   // URL to redirect for step-up authentication (default: "/_step_up")
	StepUpSessionKey string   // Session key for step-up verified flag (default: "step_up_verified")

	// Auth refresh
	AuthRefreshEnabled  bool
	AuthRefreshInterval time.Duration // Interval between auth info refreshes (default: 5 minutes)

	// Response configuration
	UserHeaderName   string // Header name for authenticated user (default: "X-Forwarded-User")
	AuthUserHeader   string // X-Auth-User header (default: "X-Auth-User")
	AuthEmailHeader  string // X-Auth-Email header (default: "X-Auth-Email")
	AuthScopesHeader string // X-Auth-Scopes header (default: "X-Auth-Scopes")
	AuthRoleHeader   string // X-Auth-Role header (default: "X-Auth-Role")
	AuthAMRHeader    string // X-Auth-AMR header (default: "X-Auth-AMR")

	// Login redirect
	AuthHost      string // Host for authentication service
	LoginPath     string // Path to login page (default: "/_login")
	CallbackParam string // Query parameter for callback URL (default: "callback")

	// Error handling
	ErrorHandler ErrorHandler

	// i18n support
	TranslateFunc TranslateFunc

	// Logging
	Logger Logger
}

// PasswordCheckFunc is a function that validates a password.
type PasswordCheckFunc func(password string) bool

// UserCheckFunc is a function that checks if a user exists in the allow list.
type UserCheckFunc func(phone, mail string) bool

// UserInfoFunc is a function that retrieves user information.
type UserInfoFunc func(phone, mail string) *UserInfo

// ErrorHandler handles authentication errors.
type ErrorHandler func(c Context, statusCode int, message string) error

// TranslateFunc translates messages based on context locale.
type TranslateFunc func(c Context, key string) string

// Logger interface for logging.
type Logger interface {
	Debug() LogEvent
	Info() LogEvent
	Warn() LogEvent
	Error() LogEvent
}

// LogEvent represents a logging event.
type LogEvent interface {
	Str(key, val string) LogEvent
	Bool(key string, val bool) LogEvent
	Int(key string, val int) LogEvent
	Int64(key string, val int64) LogEvent
	Dur(key string, val time.Duration) LogEvent
	Err(err error) LogEvent
	Msg(msg string)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		SessionEnabled:      true,
		PasswordEnabled:     false,
		PasswordHeader:      "Stargate-Password",
		HeaderAuthEnabled:   false,
		HeaderAuthUserPhone: "X-User-Phone",
		HeaderAuthUserMail:  "X-User-Mail",
		StepUpEnabled:       false,
		StepUpURL:           "/_step_up",
		StepUpSessionKey:    "step_up_verified",
		AuthRefreshEnabled:  false,
		AuthRefreshInterval: 5 * time.Minute,
		UserHeaderName:      "X-Forwarded-User",
		AuthUserHeader:      "X-Auth-User",
		AuthEmailHeader:     "X-Auth-Email",
		AuthScopesHeader:    "X-Auth-Scopes",
		AuthRoleHeader:      "X-Auth-Role",
		AuthAMRHeader:       "X-Auth-AMR",
		LoginPath:           "/_login",
		CallbackParam:       "callback",
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.PasswordEnabled && c.PasswordCheckFunc == nil {
		if len(c.ValidPasswords) == 0 {
			return ErrNoPasswordConfigured
		}
	}

	if c.HeaderAuthEnabled && c.HeaderAuthCheckFunc == nil {
		return ErrNoUserCheckFunc
	}

	return nil
}

// ApplyDefaults fills in default values for empty fields.
func (c *Config) ApplyDefaults() {
	defaults := DefaultConfig()

	if c.PasswordHeader == "" {
		c.PasswordHeader = defaults.PasswordHeader
	}
	if c.HeaderAuthUserPhone == "" {
		c.HeaderAuthUserPhone = defaults.HeaderAuthUserPhone
	}
	if c.HeaderAuthUserMail == "" {
		c.HeaderAuthUserMail = defaults.HeaderAuthUserMail
	}
	if c.StepUpURL == "" {
		c.StepUpURL = defaults.StepUpURL
	}
	if c.StepUpSessionKey == "" {
		c.StepUpSessionKey = defaults.StepUpSessionKey
	}
	if c.AuthRefreshInterval == 0 {
		c.AuthRefreshInterval = defaults.AuthRefreshInterval
	}
	if c.UserHeaderName == "" {
		c.UserHeaderName = defaults.UserHeaderName
	}
	if c.AuthUserHeader == "" {
		c.AuthUserHeader = defaults.AuthUserHeader
	}
	if c.AuthEmailHeader == "" {
		c.AuthEmailHeader = defaults.AuthEmailHeader
	}
	if c.AuthScopesHeader == "" {
		c.AuthScopesHeader = defaults.AuthScopesHeader
	}
	if c.AuthRoleHeader == "" {
		c.AuthRoleHeader = defaults.AuthRoleHeader
	}
	if c.AuthAMRHeader == "" {
		c.AuthAMRHeader = defaults.AuthAMRHeader
	}
	if c.LoginPath == "" {
		c.LoginPath = defaults.LoginPath
	}
	if c.CallbackParam == "" {
		c.CallbackParam = defaults.CallbackParam
	}
}

// StepUpMatcher handles step-up authentication path matching.
type StepUpMatcher struct {
	patterns []*regexp.Regexp
	enabled  bool
}

// NewStepUpMatcher creates a new StepUpMatcher from the given path patterns.
// Patterns support glob-style wildcards: * matches any characters, ? matches a single character.
func NewStepUpMatcher(enabled bool, pathPatterns []string) *StepUpMatcher {
	if !enabled {
		return &StepUpMatcher{enabled: false}
	}

	patterns := make([]*regexp.Regexp, 0, len(pathPatterns))
	for _, pathStr := range pathPatterns {
		pathStr = strings.TrimSpace(pathStr)
		if pathStr == "" {
			continue
		}

		// Convert glob pattern to regex
		// Simple conversion: * -> .*, ? -> ., ^ and $ for exact match
		regexPattern := "^" + strings.ReplaceAll(
			strings.ReplaceAll(regexp.QuoteMeta(pathStr), "\\*", ".*"),
			"\\?", ".",
		) + "$"

		pattern, err := regexp.Compile(regexPattern)
		if err != nil {
			// Skip invalid patterns
			continue
		}
		patterns = append(patterns, pattern)
	}

	return &StepUpMatcher{
		patterns: patterns,
		enabled:  enabled,
	}
}

// RequiresStepUp checks if the given path requires step-up authentication.
func (m *StepUpMatcher) RequiresStepUp(path string) bool {
	if !m.enabled {
		return false
	}

	if len(m.patterns) == 0 {
		return false
	}

	for _, pattern := range m.patterns {
		if pattern.MatchString(path) {
			return true
		}
	}

	return false
}

// IsEnabled returns whether step-up matching is enabled.
func (m *StepUpMatcher) IsEnabled() bool {
	return m.enabled
}

// PatternCount returns the number of configured patterns.
func (m *StepUpMatcher) PatternCount() int {
	return len(m.patterns)
}
