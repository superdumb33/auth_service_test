package services

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/superdumb33/auth-service-test/internal/entities"
	"github.com/superdumb33/auth-service-test/internal/token"
	"golang.org/x/crypto/bcrypt"
)

var (
	//errors
	ErrInternal     = entities.ErrInternal
	ErrRevoked      = entities.ErrRevoked
	ErrUnauthorized = entities.ErrUnauthorized

	//funcs
	GenerateAccessToken = token.GenerateAccessToken
	GenerateRefreshToken = token.GenerateRefreshToken
	GenerateBCryptHash = token.GenerateBCryptHash
	VerifyRefreshToken = token.VerifyRefreshToken
	ParseJWTToken = token.ParseJWTToken
)

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

type AuthRepo interface {
	Create(ctx context.Context, rt *entities.RefreshToken) error
	GetTokenByID(ctx context.Context, id uuid.UUID) (*entities.RefreshToken, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
}

type HTTPClient interface {
	NotifyIPChange(ctx context.Context, userID uuid.UUID, oldIP, newIP string)
}

type AuthService struct {
	accesTTL   time.Duration
	refreshTTL time.Duration
	repo       AuthRepo
	client     HTTPClient
}

func NewAuthService(repo AuthRepo, accessTTL, refreshTTL time.Duration, client HTTPClient) *AuthService {
	return &AuthService{repo: repo, accesTTL: accessTTL, refreshTTL: refreshTTL, client: client}
}

func (as *AuthService) GenerateTokens(ctx context.Context, userID uuid.UUID, userIP, userAgent string) (Tokens, error) {
	const op = "service:GenerateTokens"
	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}

	refreshTokenHash, err := GenerateBCryptHash(refreshToken)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}

	rt := &entities.RefreshToken{
		UserID:    userID,
		Hash:      string(refreshTokenHash),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(as.refreshTTL),
		UserAgent: userAgent,
		IPAddress: userIP,
	}
	if err := as.repo.Create(ctx, rt); err != nil {
		return Tokens{}, err
	}

	accesToken, err := GenerateAccessToken(rt.ID.String(), as.accesTTL)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}

	return Tokens{
		AccessToken:  accesToken,
		RefreshToken: refreshToken,
	}, nil

}

func (as *AuthService) Refresh(ctx context.Context, accessToken, refreshToken, userIP, userAgent string) (Tokens, error) {
	const op = "service:Refresh"
	jwtToken, err := ParseJWTToken(accessToken, true)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}
	claims := jwtToken.Claims.(jwt.MapClaims)
	jti := claims["jti"].(string)
	parsedJTI, err := uuid.Parse(jti)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}

	session, err := as.repo.GetTokenByID(ctx, parsedJTI)
	if err != nil {
		return Tokens{}, err
	}

	if session.Revoked {
		return Tokens{}, ErrRevoked
	}

	if userAgent != session.UserAgent {
		if err := as.repo.Revoke(ctx, session.ID); err != nil {
			return Tokens{}, err
		}
		return Tokens{}, fmt.Errorf("%s:%w", op, ErrUnauthorized)
	}
	//if refresh token is expired - error is returned and the session is marked as revoked
	if time.Now().After(session.ExpiresAt) {
		as.repo.Revoke(ctx, session.ID)
		return Tokens{}, fmt.Errorf("%s:%w", op, entities.ErrExpired)
	}

	if err := VerifyRefreshToken(refreshToken, session.Hash); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			if err := as.repo.Revoke(ctx, session.ID); err != nil {
				return Tokens{}, err
			}
		}

		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}

	if session.IPAddress != userIP {
		go as.client.NotifyIPChange(ctx, session.UserID, session.IPAddress, userIP)
	}

	//revoking old session. it's better to use trx to do this
	if err := as.repo.Revoke(ctx, session.ID); err != nil {
		return Tokens{}, err
	}

	newRefreshToken, err := GenerateRefreshToken()
	if err != nil {
		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}

	newHash, err := GenerateBCryptHash(newRefreshToken)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}

	rt := &entities.RefreshToken{
		UserID:    session.UserID,
		Hash:      string(newHash),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(as.refreshTTL),
		UserAgent: session.UserAgent,
		IPAddress: userIP,
	}
	if err := as.repo.Create(ctx, rt); err != nil {
		return Tokens{}, err
	}

	newAccessToken, err := GenerateAccessToken(rt.ID.String(), as.accesTTL)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s:%w", op, err)
	}

	return Tokens{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (as *AuthService) Logout(ctx context.Context, jti uuid.UUID) error {
	return as.repo.Revoke(ctx, jti)
}

func (as *AuthService) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	return as.repo.RevokeAllByUserID(ctx, userID)
}
