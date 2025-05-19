package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/superdumb33/auth-service-test/internal/entities"
	"github.com/superdumb33/auth-service-test/internal/services"
)

type MockAuthRepo struct {
	Tokens map[string]*entities.RefreshToken
}

func (mr *MockAuthRepo) Create(ctx context.Context, rt *entities.RefreshToken) error {
	rt.ID = uuid.New()
	mr.Tokens[rt.ID.String()] = rt
	return nil
}

func (mr *MockAuthRepo) GetTokenByID(ctx context.Context, id uuid.UUID) (*entities.RefreshToken, error) {
	token, ok := mr.Tokens[id.String()]
	if !ok {
		return nil, errors.New("not found")
	}
	return token, nil
}

func (mr *MockAuthRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (mr *MockAuthRepo) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	return nil
}

type MockHTTPClient struct {
}

func (mc *MockHTTPClient) NotifyIPChange(ctx context.Context, userID uuid.UUID, oldIP, newIP string) {
}	

func TestAuthService_GenerateTokens(t *testing.T) {
	// сохраним оригинальные функции
	origRefreshGenFunc := services.GenerateRefreshToken
	origBCryptGenFunc := services.GenerateBCryptHash
	origAccessGenFunc := services.GenerateAccessToken
	defer func() {
		services.GenerateRefreshToken = origRefreshGenFunc
		services.GenerateBCryptHash = origBCryptGenFunc
		services.GenerateAccessToken = origAccessGenFunc
	}()

	testUserID := uuid.New()

	mockRepo := &MockAuthRepo{Tokens: make(map[string]*entities.RefreshToken)}
	service := services.NewAuthService(mockRepo, time.Minute*5, time.Hour, &MockHTTPClient{})

	t.Run("Success", func(t *testing.T) {
		services.GenerateRefreshToken = func() (string, error) {
			return "mock-refresh-token", nil
		}

		services.GenerateBCryptHash = func(token string) ([]byte, error) {
			return []byte("mock-bcrypt-hash"), nil
		}

		services.GenerateAccessToken = func(jti string, ttl time.Duration) (string, error) {
			return "mock-access-token", nil
		}

		tokens, err := service.GenerateTokens(context.Background(), testUserID, "123.123.123.123", "agent1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tokens.AccessToken != "mock-access-token" || tokens.RefreshToken != "mock-refresh-token" {
			t.Fatalf("unexpected token values: %+v", tokens)
		}
	})

	t.Run("RefreshToken generation fails", func(t *testing.T) {
		services.GenerateRefreshToken = func() (string, error) {
			return "", errors.New("generation failed")
		}

		_, err := service.GenerateTokens(context.Background(), testUserID, "123.123.123.123", "agent1")
		if err == nil || err.Error() != "service:GenerateTokens:generation failed" {
			t.Fatalf("expected generation failed error, got: %v", err)
		}
	})

	t.Run("BCryptHash fails", func(t *testing.T) {
		services.GenerateRefreshToken = func() (string, error) {
			return "rt", nil
		}

		services.GenerateBCryptHash = func(token string) ([]byte, error) {
			return nil, errors.New("bcrypt fail")
		}

		_, err := service.GenerateTokens(context.Background(), testUserID, "123.123.123.123", "agent1")
		if err == nil || err.Error() != "service:GenerateTokens:bcrypt fail" {
			t.Fatalf("expected bcrypt fail error, got: %v", err)
		}
	})

	t.Run("AccessToken generation fails", func(t *testing.T) {
		services.GenerateRefreshToken = func() (string, error) {
			return "rt", nil
		}

		services.GenerateBCryptHash = func(token string) ([]byte, error) {
			return []byte("hash"), nil
		}

		services.GenerateAccessToken = func(jti string, ttl time.Duration) (string, error) {
			return "", errors.New("access token fail")
		}

		_, err := service.GenerateTokens(context.Background(), testUserID, "123.123.123.123", "agent1")
		if err == nil || err.Error() != "service:GenerateTokens:access token fail" {
			t.Fatalf("expected access token fail error, got: %v", err)
		}
	})
}
func TestAuthService_Refresh(t *testing.T) {
	originalFunc := services.ParseJWTToken
	defer func() {
		services.ParseJWTToken = originalFunc
	}()

	testUserID := uuid.New()
	testJTI := uuid.MustParse("08df6071-fa54-4ddd-a76e-11f2fb168363")
	testRefreshToken := "refresh-plaintext"
	testRefreshTokenHash := "$2b$12$I3D4cWeWmuaOIiSE5WSvZejPMwwaXwIOxOxIwv9fXvvgpoR0Qnxti"
	testAccessToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDc2NDM2MDUsImp0aSI6IjA4ZGY2MDcxLWZhNTQtNGRkZC1hNzZlLTExZjJmYjE2ODM2MyJ9.m1HgRrDZSHkPxYyjowWP9D1M7ek6xwCSG9y0yM9EfetjLQ_g_lKEpuRbiWKneLVV43P4UL-Kd1PHDcb-bumVTg"

	mockRepo := &MockAuthRepo{
		Tokens: map[string]*entities.RefreshToken{
			testJTI.String(): {
				ID:        testJTI,
				UserID:    testUserID,
				Hash:      testRefreshTokenHash,
				ExpiresAt: time.Now().Add(time.Hour),
				UserAgent: "agent1",
				IPAddress: "123.123.123.123",
			},
		},
	}

	services.ParseJWTToken = func(token string, _ bool) (*jwt.Token, error) {
		return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			return []byte("super-secret"), nil
		})
	}

	service := services.NewAuthService(mockRepo, time.Minute*5, time.Hour, &MockHTTPClient{})

	t.Run("Success", func(t *testing.T) {
		tokens, err := service.Refresh(context.Background(), testAccessToken, testRefreshToken, "1.1.1.1", "agent1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tokens.AccessToken == "" || tokens.RefreshToken == "" {
			t.Fatal("expected non-empty tokens")
		}
	})

	t.Run("Mismatched UserAgent", func(t *testing.T) {
		_, err := service.Refresh(context.Background(), testAccessToken, testRefreshToken, "1.1.1.1", "agent2")
		if !errors.Is(err, entities.ErrUnauthorized) {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
	})

	t.Run("Mismatched Refresh Token", func(t *testing.T) {
		_, err := service.Refresh(context.Background(), testAccessToken, "wrong-token", "123.123.123.123", "agent1")
		if err == nil {
			t.Fatal("expected error due to refresh token mismatch")
		}
	})

	t.Run("Expired Refresh Token", func(t *testing.T) {
		mockRepo.Tokens[testJTI.String()].ExpiresAt = time.Now().Add(time.Second-1)
		_, err := service.Refresh(context.Background(), testAccessToken, testRefreshToken, "123.123.123.123", "agent1")
		if !errors.Is(err, entities.ErrExpired) {
			t.Fatalf("expected ErrExpired, got %v", err)
		}
	})
}
