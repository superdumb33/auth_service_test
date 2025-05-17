package controllers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/superdumb33/auth-service-test/internal/services"
	"github.com/superdumb33/auth-service-test/internal/token"
)

func AuthMiddleware(repo services.AuthRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := strings.TrimPrefix(c.Get("Authorization"), "Bearer ")
		if tokenString == "" {
			return c.Status(401).SendString("empty authorization header")
		}

		token, err := token.ParseJWTToken(tokenString, false)
		if err != nil || !token.Valid {
			return c.Status(401).SendString("Unauthorized")
		}

		claims := token.Claims.(jwt.MapClaims)
		jtiString := claims["jti"].(string)
		jti, err := uuid.Parse(jtiString)
		if err != nil {
			return c.Status(401).SendString("Unauthorized")
		}

		session, err := repo.GetTokenByID(c.Context(), jti)
		if err != nil {
			return err
		}

		if session == nil || session.Revoked {
			return c.Status(401).SendString("Unauthorized: session revoked")
		}

		if session.UserAgent != c.Get("User-Agent") {
			if err := repo.Revoke(c.Context(), session.ID); err != nil {
				return c.Status(500).JSON(fiber.Map{
					"error": "Internal server error",
				})
			}

			return c.Status(401).JSON(fiber.Map{
				"error": "user-agent change detected, session revoked",
			})
		}

		c.Locals("userid", session.UserID)
		c.Locals("jti", session.ID)

		return c.Next()

	}
}
