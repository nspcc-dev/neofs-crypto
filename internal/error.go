package internal

// Error is a custom error returned from the library.
type Error string

// Error is an implementation of error interface.
func (e Error) Error() string { return string(e) }
