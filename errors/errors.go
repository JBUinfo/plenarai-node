package errors

import "fmt"

type CLIError struct {
	Code    string
	Message string
}

func (e *CLIError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func New(code, message string) *CLIError {
	return &CLIError{Code: code, Message: message}
}

var (
	ErrNotAuthenticated = New("AUTH_REQUIRED", "you must login first")
	ErrConnectionFailed = New("CONN_FAILED", "could not connect to server")
	ErrInsufficientFunds = New("NO_FUNDS", "insufficient credits in your account")
)
