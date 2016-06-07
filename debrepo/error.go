package debrepo

// Error is a const error type.
type Error string

func (e Error) Error() string {
	return string(e)
}
