package model

type Error struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
}

func NewError(code int, reason string) *Error {
	return &Error{
		Code:   code,
		Reason: reason,
	}
}
