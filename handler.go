package forwardauth

import (
	"net/url"
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

	// Check step-up requirement.
	//
	// The path matched must be the *original* request's path. In a ForwardAuth
	// deployment the proxy calls this endpoint at a fixed URL (/_auth in the
	// README's own nginx config) and passes the real target in X-Forwarded-Uri,
	// so matching c.Path() compared the patterns against "/_auth" every time
	// and never fired. Step-up was configured and silently inert.
	if h.stepUpMatcher != nil && h.stepUpRequiredFor(c) {
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
		// Replace, do not merge. Only overwriting non-empty values meant a
		// user whose scopes had been revoked to none, or whose role had been
		// cleared, kept the privileges already in their session forever: the
		// refresh could raise privileges but never lower them.
		sess.Set(KeyUserScope, userInfo.Scopes)
		result.Scopes = userInfo.Scopes
		sess.Set(KeyUserRole, userInfo.Role)
		result.Role = userInfo.Role
		// Name is explicitly optional, unlike Scopes and Role: a refresh
		// callback that returns only authorization data legitimately leaves it
		// empty. Replacing it unconditionally erased KeyUserName -- and with
		// it the X-Auth-Name header -- after the first refresh. Only scopes and
		// role need replace semantics, because that is what revocation looks
		// like.
		if userInfo.Name != "" {
			sess.Set(KeyUserName, userInfo.Name)
			result.Name = userInfo.Name
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
		// The user no longer exists, or the directory is unreachable. Either
		// way the session's cached authorisation can no longer be vouched for,
		// so it is dropped rather than left in place: a deleted or suspended
		// account kept its privileges for as long as the lookup kept failing.
		alreadyCleared := clearedAuthorization(sess)

		sess.Set(KeyUserScope, []string{})
		sess.Set(KeyUserRole, "")
		result.Scopes = nil
		result.Role = ""
		result.AuthRefreshFailed = true

		// Save only when there was something to clear.
		//
		// KeyAuthRefreshedAt is deliberately NOT advanced on failure -- a
		// refresh that did not happen must not read as one that did -- so
		// every subsequent request during a directory outage arrives here
		// again. Saving each time wrote the same empty scope and empty role
		// to the session backend on every request, for as long as the outage
		// lasted. The clearing itself still happens on every pass: it is the
		// write that is redundant, not the decision.
		if !alreadyCleared {
			if err := sess.Save(); err != nil {
				if h.config.Logger != nil {
					h.config.Logger.Warn().Err(err).Msg("Failed to save session after clearing stale authorization")
				}
			}
		}

		if h.config.Logger != nil {
			h.config.Logger.Warn().
				Dur("duration", refreshDuration).
				Msg("Failed to refresh auth info: user not found, cleared cached authorization")
		}
	}
}

// clearedAuthorization reports whether the session already holds the cleared
// authorization that a failed refresh writes: no role and no scopes.
//
// A value of an unexpected type counts as NOT cleared, so the failure path
// still overwrites it. Absent counts as cleared -- there is nothing to
// replace, and an absent role reaches BuildHeaders exactly as an empty one
// does.
func clearedAuthorization(sess Session) bool {
	switch role := sess.Get(KeyUserRole).(type) {
	case nil:
	case string:
		if role != "" {
			return false
		}
	default:
		return false
	}

	switch scopes := sess.Get(KeyUserScope).(type) {
	case nil:
		return true
	case []string:
		return len(scopes) == 0
	default:
		return false
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
		// The callback URL contains "://" and its own query string, so it has
		// to be escaped before being used as a query parameter value.
		stepUpURL := h.config.StepUpURL + "?" + url.QueryEscape(h.config.CallbackParam) + "=" + url.QueryEscape(callbackURL)
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

// stepUpRequiredFor reports whether this request's target is a step-up route.
//
// The target comes from X-Forwarded-Uri, which only the proxy should be able
// to set. When the deployment has not declared that its proxy OVERWRITES that
// header (StepUpForwardedURITrusted), a present value may have been chosen by
// the client -- Traefik with trustForwardHeader: true forwards it verbatim --
// so "this route is not protected" is not a conclusion that can be drawn from
// it. Such a request is treated as protected: failing closed costs a step-up
// prompt, failing open costs the control entirely.
//
// A request carrying no usable forwarded path is treated as protected for the
// same reason, and this is why it does not fall back to the request's own path.
// Context.Get cannot tell an absent header from one present and empty -- Go's
// http.Header and Fiber both answer "" for each -- so neither can this, and an
// authenticated client only had to send a bare "X-Forwarded-Uri:" to turn the
// question into one about the auth endpoint. In a ForwardAuth deployment that
// endpoint is at a fixed path (/_auth in the README's own Traefik and nginx
// configurations), it matches no step-up pattern, and so the fallback could
// only ever answer "not protected" -- for the forged request and the honest
// one alike.
//
// The cost is that a proxy which does not set X-Forwarded-Uri at all now gets
// a step-up prompt on every request. That deployment had no working step-up
// control to begin with, for exactly the reason above: every path it tested
// was /_auth. A prompt is how that misconfiguration becomes visible instead of
// silently disabling the control.
func (h *Handler) stepUpRequiredFor(c Context) bool {
	// Nothing is protected, so there is nothing to fail closed about. A
	// matcher with no usable patterns answers false for every path by
	// definition -- StepUpEnabled with an empty or all-blank StepUpPaths
	// builds exactly that -- and the rule below would otherwise invert it into
	// step-up on every route for a configuration asking for it on none.
	if h.stepUpMatcher.PatternCount() == 0 {
		return false
	}

	forwarded := c.Get("X-Forwarded-Uri")
	raw := forwardedPath(forwarded)
	if raw == "" || !h.config.StepUpForwardedURITrusted {
		return true
	}
	// Both spellings: the bytes as forwarded, and the decoded/cleaned path a
	// downstream router routes on. Either one matching means step-up, so an
	// encoded "/%61dmin/settings" cannot slip past a "/admin/*" pattern that
	// the router itself will honour.
	if h.stepUpMatcher.RequiresStepUp(raw) {
		return true
	}
	if canonical := canonicalForwardedPath(forwarded); canonical != raw {
		return h.stepUpMatcher.RequiresStepUp(canonical)
	}
	return false
}
