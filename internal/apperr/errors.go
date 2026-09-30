// Package apperr defines distinguishable application error codes.
package apperr

import "fmt"

// Code identifies a category of rejection or failure.
type Code string

const (
	CodeMalformedJSON Code = "MALFORMED_JSON"
	CodeMissingField  Code = "MISSING_FIELD"
	CodeValueTooLarge Code = "VALUE_TOO_LARGE"
	CodeUnknownSource Code = "UNKNOWN_SOURCE"
	CodePolicyFailure Code = "POLICY_FAILURE"
	CodeInternal      Code = "INTERNAL_ERROR"
	CodeNotFound      Code = "NOT_FOUND"
	CodeAccessDenied  Code = "ACCESS_DENIED"
)

// Error is a coded, explainable application error.
type Error struct {
	Code    Code
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// New builds a coded error.
func New(code Code, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// Wrap wraps a cause with a coded error.
func Wrap(code Code, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, Cause: cause}
}
