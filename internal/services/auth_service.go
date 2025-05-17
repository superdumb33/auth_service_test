package services

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/superdumb33/auth-service-test/internal/entities"
	"github.com/superdumb33/auth-service-test/internal/token"
)

type Tokens struct {
	AccessToken string
	RefreshToken string
}

type AuthRepo interface {
	Create(ctx context.Context, rt *entities.RefreshToken) error
	GetTokenByID(ctx context.Context, id uuid.UUID) (*entities.RefreshToken, error)
	Revoke(ctx context.Context, id uuid.UUID) error

}

type AuthService struct {
	accesTTL time.Duration
	refreshTTL time.Duration
	repo AuthRepo
}

func NewAuthService(repo AuthRepo, accessTTL, refreshTTL time.Duration) *AuthService {
	return &AuthService{repo: repo, accesTTL: accessTTL, refreshTTL: refreshTTL}
}

func (as *AuthService) GenerateTokens(ctx context.Context, userID uuid.UUID, userIP, userAgent string) (Tokens, error) {
	refreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		return Tokens{}, err
	}

	refreshTokenHash, err := token.GenerateBCryptHash(refreshToken) 
	if err != nil {
		return Tokens{}, err
	}

	rt := &entities.RefreshToken{
		UserID: userID,
		Hash: string(refreshTokenHash),
		IssuedAt: time.Now(),
		ExpiresAt: time.Now().Add(as.refreshTTL),
		UserAgent: userAgent,
		IPAddress: userIP,
	}
	if err := as.repo.Create(ctx, rt); err != nil {
		return Tokens{}, err
	}

	accesToken, err := token.GenerateAccessToken(rt.ID.String(), as.accesTTL)
	if err != nil {
		return Tokens{}, err
	}

	return Tokens{
		AccessToken: accesToken,
		RefreshToken: refreshToken,
	}, nil

}

func (as *AuthService) Refresh (ctx context.Context, accessToken, refreshToken, userIP , userAgent string) (Tokens, error) {
	jwtToken, err := token.ParseJWTToken(accessToken, true)
	if err != nil {
		return Tokens{}, err
	}
	claims := jwtToken.Claims.(jwt.MapClaims)
	jti := claims["jti"].(string)
	parsedJTI, err := uuid.Parse(jti)
	if err != nil {
		return Tokens{}, err
	}

	session, err := as.repo.GetTokenByID(ctx, parsedJTI)
	if err != nil {
		return Tokens{}, err
	}

	if err := token.VerifyRefreshToken(refreshToken, session.Hash); err != nil {
		return Tokens{}, err
	}
	//if refresh token is expired - error is returned and the session is marked as revoked
	if time.Now().After(session.ExpiresAt) || userAgent != session.UserAgent {
		as.repo.Revoke(ctx, session.ID)
		//REPLACE ERR
		return Tokens{}, err
	}

	if err := as.repo.Revoke(ctx, session.ID); err != nil {
		return Tokens{}, err
	}

	newRefreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		return Tokens{}, err
	}

	newHash, err := token.GenerateBCryptHash(newRefreshToken)
	if err != nil {
		return Tokens{}, err
	}

	
	rt := &entities.RefreshToken{
		UserID: session.UserID,
		Hash: string(newHash),
		IssuedAt: time.Now(),
		ExpiresAt: time.Now().Add(as.refreshTTL),
		UserAgent: session.UserAgent,
		IPAddress: userIP,
	}
	if err := as.repo.Create(ctx, rt); err != nil {
		return Tokens{}, err
	}

	newAccessToken, err := token.GenerateAccessToken(rt.ID.String(), as.accesTTL)
	if err != nil {
		return Tokens{}, err
	}

	return Tokens{
		AccessToken: newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (as *AuthService) Logout (ctx context.Context, jti uuid.UUID) error {
	return as.repo.Revoke(ctx, jti)
}