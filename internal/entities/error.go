package entities

import "errors"

var (
	ErrNotFound = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
	ErrInternal = errors.New("internal server error")
	ErrExpired = errors.New("expired")
	ErrBadRequest = errors.New("bad request")
	ErrUnauthorized = errors.New("unauthorized")
	ErrRevoked = errors.New("revoked")
)