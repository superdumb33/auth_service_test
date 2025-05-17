package entities

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID uuid.UUID
	UserID uuid.UUID
	Hash string
	IssuedAt time.Time
	ExpiresAt time.Time
	UserAgent string
	IPAddress string
	Revoked bool
}