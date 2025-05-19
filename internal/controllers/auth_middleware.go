package controllers

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/superdumb33/auth-service-test/internal/entities"
	"github.com/superdumb33/auth-service-test/internal/services"
	"github.com/superdumb33/auth-service-test/internal/token"
)

var (
	ErrUnauthorized = entities.ErrUnauthorized
	ErrExpired = entities.ErrExpired
)

func AuthMiddleware(repo services.AuthRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		const op = "authmiddleware:"
		tokenString := strings.TrimPrefix(c.Get("Authorization"), "Bearer ")
		if tokenString == "" {
			return fmt.Errorf("%s:%w", op, ErrUnauthorized)
		}

		token, err := token.ParseJWTToken(tokenString, false)
		if err != nil || !token.Valid {
			if err == jwt.ErrTokenExpired {
				return fmt.Errorf("%s:%w", op, ErrExpired)
			}
			return fmt.Errorf("%s:%w", op, ErrUnauthorized)
		}

		claims := token.Claims.(jwt.MapClaims)
		jtiString := claims["jti"].(string)
		jti, err := uuid.Parse(jtiString)
		if err != nil {
			return fmt.Errorf("%s:%w", op, ErrUnauthorized)
		}

		session, err := repo.GetTokenByID(c.Context(), jti)
		if err != nil {
			return err
		}

		if session == nil || session.Revoked {
			return fmt.Errorf("%s:%w", op, ErrUnauthorized)
		}

		if session.UserAgent != c.Get("User-Agent") {
			if err := repo.Revoke(c.Context(), session.ID); err != nil {
				return err
			}

			return fmt.Errorf("%s:%w", op, ErrUnauthorized)
		}

		c.Locals("userid", session.UserID)
		c.Locals("jti", session.ID)

		return c.Next()

	}
}
