package pgxrepo

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superdumb33/auth-service-test/internal/entities"
)

var (
	ErrNotFound = entities.ErrNotFound
	ErrDuplicate = entities.ErrDuplicate
	ErrInternal = entities.ErrInternal
)

type PgxAuthRepo struct {
	db *pgxpool.Pool
}

func NewPgxAuthRepo(db *pgxpool.Pool) *PgxAuthRepo {
	return &PgxAuthRepo{db: db}
}

func (ar *PgxAuthRepo) Create(ctx context.Context, rt *entities.RefreshToken) error {
	const op = "repo:Create"
	query := `INSERT INTO refresh_tokens (user_id, token_hash, issued_at, expires_at, user_agent, ip_address)
	VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`

	if err := ar.db.QueryRow(ctx, query, rt.UserID, rt.Hash, rt.IssuedAt, rt.ExpiresAt, rt.UserAgent, rt.IPAddress).Scan(&rt.ID); err != nil {
		return fmt.Errorf("%s:%w", op, err)
	}

	return nil
}

func (ar *PgxAuthRepo) GetTokenByID(ctx context.Context, id uuid.UUID) (*entities.RefreshToken, error) {
	const op = "repo:GetTokenByID"
	var token entities.RefreshToken
	query := `SELECT id, user_id, token_hash, issued_at, expires_at, user_agent, ip_address, revoked 
	FROM refresh_tokens WHERE id = $1`
	err := ar.db.QueryRow(ctx, query, id).Scan(&token.ID, &token.UserID, &token.Hash, &token.IssuedAt, &token.ExpiresAt, &token.UserAgent, &token.IPAddress, &token.Revoked)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("%s:%w", op, ErrNotFound)
		}
		return nil, fmt.Errorf("%s:%w", op, err)
	}

	return &token, nil
}

func (ar *PgxAuthRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	const op = "repo:Revoke"
	query := `UPDATE refresh_tokens SET revoked = true WHERE id=$1`
	tag, err := ar.db.Exec(ctx, query, id)
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s:%w", op, ErrNotFound)
	}

	return err
}

func (ar *PgxAuthRepo) RevokeAllByUserID (ctx context.Context, userID uuid.UUID) error {
	const op = "repo:RevokeAllByUserID"
	query := `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1`
	tag, err := ar.db.Exec(ctx, query, userID)
	if tag.RowsAffected() == 0{
		return fmt.Errorf("%s:%w", op, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("%s:%w", op, err)
	}

	return nil
}