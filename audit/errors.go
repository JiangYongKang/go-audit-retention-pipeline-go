package audit

import "errors"

// Code 是可机读的拒绝 / 失败原因码。接入方必须能据此区分
// 格式错误、字段缺失、超限、重复、内部失败与权限问题。
type Code string

const (
	CodeFormat           Code = "malformed_format"
	CodeMissingField     Code = "missing_field"
	CodeOversized        Code = "oversized"
	CodeUnknownSource    Code = "unknown_source"
	CodeDuplicate        Code = "duplicate_event"
	CodeInternal         Code = "internal_error"
	CodeUnauthenticated  Code = "unauthenticated"
	CodePermissionDenied Code = "permission_denied"
	CodeInvalidFilter    Code = "invalid_filter"
	CodeClosed           Code = "pipeline_closed"
)

// Error 携带稳定错误码与触发字段，便于调用方区分处理。
type Error struct {
	Code  Code
	Field string
	Msg   string
	Cause error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	s := string(e.Code)
	if e.Field != "" {
		s += " (" + e.Field + ")"
	}
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	if e.Cause != nil {
		s += ": " + e.Cause.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Cause }

func newError(code Code, field, msg string, cause error) *Error {
	return &Error{Code: code, Field: field, Msg: msg, Cause: cause}
}

// AsError 从任意错误中提取 *Error（支持包装链）。
func AsError(err error) (*Error, bool) {
	if err == nil {
		return nil, false
	}
	var ae *Error
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// IsCode 判断错误链上是否存在指定原因码。
func IsCode(err error, code Code) bool {
	if ae, ok := AsError(err); ok {
		return ae.Code == code
	}
	return false
}
