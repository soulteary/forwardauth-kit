package forwardauth

import (
	"sort"
	"time"
)

// Handler is the main ForwardAuth handler.
type Handler struct {
	config        *Config
	checkers      []AuthChecker
	stepUpMatcher *StepUpMatcher
	headerBuilder *AuthHeaderBuilder
	forwarded     ForwardedHeaders
}

// NewHandler creates a new ForwardAuth handler.
func NewHandler(config *Config) *Handler {
	config.ApplyDefaults()

	h := &Handler{
		config:        config,
		checkers:      make([]AuthChecker, 0),
		headerBuilder: NewAuthHeaderBuilder(config),
	}

	// Initialize step-up matcher if enabled
	if config.StepUpEnabled {
		h.stepUpMatcher = NewStepUpMatcher(true, config.StepUpPaths)
	}

	// Add checkers based on configuration
	if config.PasswordEnabled {
		h.AddChecker(NewPasswordChecker(config))
	}
	if config.HeaderAuthEnabled {
		h.AddChecker(NewHeaderChecker(config))
	}
	if config.SessionEnabled {
		h.AddChecker(NewSessionChecker(config))
	}

	return h
}

// AddChecker adds an authentication checker to the handler.
func (h *Handler) AddChecker(checker AuthChecker) {
	h.checkers = append(h.checkers, checker)
	// Sort by priority (lower = higher priority)
	sort.Slice(h.checkers, func(i, j int) bool {
		return h.checkers[i].Priority() < h.checkers[j].Priority()
	})
}

// Check performs the full authentication check.
func (h *Handler) Check(c Context, sess Session) (*AuthResult, error) {
	var lastErr error
	var result *AuthResult

	// Try each checker in priority order
	for _, checker := range h.checkers {
		r, err := checker.Check(c, sess)
		if err != nil {
			lastErr = err
			if h.config.Logger != nil {
				h.config.Logger.Debug().
					Str("checker", checker.Name()).
					Err(err).
					Msg("Auth checker failed")
			}
			continue
		}
		if r != nil && r.Authenticated {
			result = r
			if h.config.Logger != nil {
				h.config.Logger.Debug().
					Str("checker", checker.Name()).
					Str("method", r.AuthMethod.String()).
					Msg("Authentication successful")
			}
			break
		}
	}

	if result == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, ErrNotAuthenticated
	}

	// Check step-up requirement
	if h.stepUpMatcher != nil && h.stepUpMatcher.RequiresStepUp(c.Path()) {
		if sess == nil {
			return nil, ErrStepUpRequired
		}

		stepUpVerified := sess.Get(h.config.StepUpSessionKey)
		if stepUpVerified == nil {
			return nil, ErrStepUpRequired
		}
		if verified, ok := stepUpVerified.(bool); !ok || !verified {
			return nil, ErrStepUpRequired
		}
	}

	// Refresh auth info if needed
	if result.NeedsRefresh && h.config.HeaderAuthGetInfoFunc != nil {
		h.refreshAuthInfo(c, sess, result)
	}

	return result, nil
}

// refreshAuthInfo refreshes the authorization information from the external source.
func (h *Handler) refreshAuthInfo(c Context, sess Session, result *AuthResult) {
	if sess == nil {
		return
	}

	userPhone := ""
	userMail := ""

	// Get identifiers from session
	if val := sess.Get(KeyUserPhone); val != nil {
		if phone, ok := val.(string); ok {
			userPhone = phone
		}
	}
	if val := sess.Get(KeyUserMail); val != nil {
		if mail, ok := val.(string); ok {
			userMail = mail
		}
	}

	if userPhone == "" && userMail == "" {
		return
	}

	// Fetch updated user info
	refreshStart := time.Now()
	userInfo := h.config.HeaderAuthGetInfoFunc(userPhone, userMail)
	refreshDuration := time.Since(refreshStart)

	if userInfo != nil {
		// Update session with fresh authorization info
		if len(userInfo.Scopes) > 0 {
			sess.Set(KeyUserScope, userInfo.Scopes)
			result.Scopes = userInfo.Scopes
		}
		if userInfo.Role != "" {
			sess.Set(KeyUserRole, userInfo.Role)
			result.Role = userInfo.Role
		}
		sess.Set(KeyAuthRefreshedAt, time.Now().Unix())
		result.RefreshedAt = time.Now()

		if err := sess.Save(); err != nil {
			if h.config.Logger != nil {
				h.config.Logger.Warn().
					Err(err).
					Msg("Failed to save session after auth refresh")
			}
		} else {
			if h.config.Logger != nil {
				h.config.Logger.Debug().
					Str("phone", userPhone).
					Str("mail", userMail).
					Dur("duration", refreshDuration).
					Msg("Auth info refreshed for user")
			}
		}
	} else {
		if h.config.Logger != nil {
			h.config.Logger.Warn().
				Dur("duration", refreshDuration).
				Msg("Failed to refresh auth info: user not found")
		}
	}
}

// SetAuthHeaders sets the authentication headers on the context.
func (h *Handler) SetAuthHeaders(c Context, result *AuthResult) {
	h.headerBuilder.SetHeaders(c, result)
}

// HandleNotAuthenticated handles unauthenticated requests.
// For HTML requests, it redirects to the login page.
// For API requests, it returns a 401 error response.
func (h *Handler) HandleNotAuthenticated(c Context) error {
	if IsHTMLRequest(c) {
		callbackURL := h.forwarded.BuildCallbackURL(c, h.config.AuthHost, h.config.LoginPath, h.config.CallbackParam)
		return c.Redirect(callbackURL)
	}

	message := "authentication required"
	if h.config.TranslateFunc != nil {
		message = h.config.TranslateFunc(c, "error.auth_required")
	}

	return h.sendErrorResponse(c, 401, message)
}

// HandleStepUpRequired handles requests that require step-up authentication.
func (h *Handler) HandleStepUpRequired(c Context) error {
	if IsHTMLRequest(c) {
		callbackURL := h.forwarded.BuildCallbackURL(c, h.config.AuthHost, h.config.LoginPath, h.config.CallbackParam)
		stepUpURL := h.config.StepUpURL + "?" + h.config.CallbackParam + "=" + callbackURL
		return c.Redirect(stepUpURL)
	}

	message := "step-up authentication required"
	if h.config.TranslateFunc != nil {
		message = h.config.TranslateFunc(c, "error.step_up_required")
	}

	return h.sendErrorResponse(c, 403, message)
}

// HandleSessionError handles session store errors.
func (h *Handler) HandleSessionError(c Context, err error) error {
	message := "session store error"
	if h.config.TranslateFunc != nil {
		message = h.config.TranslateFunc(c, "error.session_store_failed")
	}

	if h.config.Logger != nil {
		h.config.Logger.Error().
			Err(err).
			Msg("Session store error")
	}

	return h.sendErrorResponse(c, 500, message)
}

// sendErrorResponse sends an error response in the appropriate format.
func (h *Handler) sendErrorResponse(c Context, statusCode int, message string) error {
	if h.config.ErrorHandler != nil {
		return h.config.ErrorHandler(c, statusCode, message)
	}

	return SendErrorResponse(c, statusCode, message)
}

// GetStepUpMatcher returns the step-up matcher.
func (h *Handler) GetStepUpMatcher() *StepUpMatcher {
	return h.stepUpMatcher
}

// GetConfig returns the handler configuration.
func (h *Handler) GetConfig() *Config {
	return h.config
}
