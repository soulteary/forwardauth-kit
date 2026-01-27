package forwardauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrors(t *testing.T) {
	// Test that error variables are defined correctly
	assert.NotNil(t, ErrNoPasswordConfigured)
	assert.NotNil(t, ErrNoUserCheckFunc)
	assert.NotNil(t, ErrInvalidConfig)
	assert.NotNil(t, ErrNotAuthenticated)
	assert.NotNil(t, ErrInvalidPassword)
	assert.NotNil(t, ErrUserNotFound)
	assert.NotNil(t, ErrSessionRequired)
	assert.NotNil(t, ErrStepUpRequired)
	assert.NotNil(t, ErrSessionStoreError)
	assert.NotNil(t, ErrUnauthorized)
	assert.NotNil(t, ErrForbidden)

	// Test error messages
	assert.Equal(t, "password authentication enabled but no passwords configured", ErrNoPasswordConfigured.Error())
	assert.Equal(t, "header authentication enabled but no user check function provided", ErrNoUserCheckFunc.Error())
	assert.Equal(t, "invalid configuration", ErrInvalidConfig.Error())
	assert.Equal(t, "not authenticated", ErrNotAuthenticated.Error())
	assert.Equal(t, "invalid password", ErrInvalidPassword.Error())
	assert.Equal(t, "user not found", ErrUserNotFound.Error())
	assert.Equal(t, "session required", ErrSessionRequired.Error())
	assert.Equal(t, "step-up authentication required", ErrStepUpRequired.Error())
	assert.Equal(t, "session store error", ErrSessionStoreError.Error())
	assert.Equal(t, "unauthorized", ErrUnauthorized.Error())
	assert.Equal(t, "forbidden", ErrForbidden.Error())
}

func TestErrorCodes(t *testing.T) {
	assert.Equal(t, ErrorCode("unauthorized"), ErrorCodeUnauthorized)
	assert.Equal(t, ErrorCode("invalid_password"), ErrorCodeInvalidPassword)
	assert.Equal(t, ErrorCode("user_not_found"), ErrorCodeUserNotFound)
	assert.Equal(t, ErrorCode("session_required"), ErrorCodeSessionRequired)
	assert.Equal(t, ErrorCode("step_up_required"), ErrorCodeStepUpRequired)
	assert.Equal(t, ErrorCode("session_error"), ErrorCodeSessionError)
	assert.Equal(t, ErrorCode("internal_error"), ErrorCodeInternalError)
}

func TestNewErrorResponse(t *testing.T) {
	tests := []struct {
		name    string
		code    ErrorCode
		message string
		status  int
	}{
		{
			name:    "unauthorized error",
			code:    ErrorCodeUnauthorized,
			message: "You are not authorized",
			status:  401,
		},
		{
			name:    "forbidden error",
			code:    ErrorCodeStepUpRequired,
			message: "Step-up authentication required",
			status:  403,
		},
		{
			name:    "internal error",
			code:    ErrorCodeInternalError,
			message: "Internal server error",
			status:  500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := NewErrorResponse(tt.code, tt.message, tt.status)

			assert.NotNil(t, resp)
			assert.False(t, resp.OK)
			assert.Equal(t, tt.code, resp.Code)
			assert.Equal(t, tt.message, resp.Message)
			assert.Equal(t, tt.status, resp.Status)
		})
	}
}

func TestErrorResponse(t *testing.T) {
	resp := &ErrorResponse{
		OK:      false,
		Code:    ErrorCodeUnauthorized,
		Message: "Not authenticated",
		Status:  401,
	}

	assert.False(t, resp.OK)
	assert.Equal(t, ErrorCodeUnauthorized, resp.Code)
	assert.Equal(t, "Not authenticated", resp.Message)
	assert.Equal(t, 401, resp.Status)
}
