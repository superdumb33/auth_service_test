package pgxrepo

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superdumb33/auth-service-test/internal/entities"
)

type PgxAuthRepo struct {
	db *pgxpool.Pool
}

func NewPgxAuthRepo(db *pgxpool.Pool) *PgxAuthRepo {
	return &PgxAuthRepo{db: db}
}

func (ar *PgxAuthRepo) Create(ctx context.Context, rt *entities.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (user_id, token_hash, issued_at, expires_at, user_agent, ip_address)
	VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`

	if err := ar.db.QueryRow(ctx, query, rt.UserID, rt.Hash, rt.IssuedAt, rt.ExpiresAt, rt.UserAgent, rt.IPAddress).Scan(&rt.ID); err != nil {
		return err
	}
	
	return nil
}

func (ar *PgxAuthRepo) GetTokenByID(ctx context.Context, id uuid.UUID) (*entities.RefreshToken, error) {
	return nil, nil
}

func (ar *PgxAuthRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	return nil
}