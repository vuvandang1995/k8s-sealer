package sealer

// General errors.
const (
	ErrUnauthorized = Error("unauthorized")
	ErrInternal     = Error("internal error")
)

// Error represents a app error.
type Error string

// Error returns the error message.
func (e Error) Error() string { return string(e) }
