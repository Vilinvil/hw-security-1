package myerrors

const ErrTemplate = "%w"

type Error struct {
	err string
}

func (e *Error) Error() string {
	return e.err
}

func NewError(err string) *Error {
	return &Error{err: err}
}
