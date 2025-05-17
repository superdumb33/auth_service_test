package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/superdumb33/auth-service-test/internal/dto"
	"github.com/superdumb33/auth-service-test/internal/services"
)

type AuthController struct {
	service *services.AuthService
}

func NewAuthController(service *services.AuthService) *AuthController {
	return &AuthController{service: service}
}


func (ac *AuthController) RegisterRoutes (router fiber.Router, authMiddleware fiber.Handler) {
	authRouter := router.Group("/auth")
	authRouter.Post("/issue", ac.Issue)
	authRouter.Post("/refresh", ac.Refresh)

	authRouterProtected := authRouter.Group("/", authMiddleware)
	authRouterProtected.Get("/me", ac.GetCurrentUserID)
	authRouterProtected.Get("/logout", ac.Logout)
}



func (ac *AuthController) Issue (c *fiber.Ctx) error {
	userID, err := uuid.Parse(c.Query("userid"))
	if err != nil {
		return c.Status(400).JSON(err)
	}
	
	userAgent := c.Get("User-Agent")
	if userAgent == "" {
		return c.Status(400).SendString("Bad request")
	}
	ip := c.IP()

	tokens, err := ac.service.GenerateTokens(c.Context(), userID, ip, userAgent)
	if err != nil {
		return err
	}

	resp := &dto.IssueTokensResponse{
		AccessToken: tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	return c.Status(200).JSON(resp)

}

func (ac *AuthController) Refresh (c *fiber.Ctx) error {
	var request dto.RefreshTokensRequest
	if err := c.BodyParser(&request); err != nil {
		return err
	}
	if request.AccessToken == "" || request.RefreshToken == "" {
		return c.Status(400).SendString("empty token")
	}
	userAgent := c.Get("User-Agent")
	if userAgent == "" {
		return c.Status(400).SendString("Bad request")
	}

	tokens, err := ac.service.Refresh(c.Context(), request.AccessToken, request.RefreshToken, c.IP(), userAgent)
	if err != nil {
		return err
	}	
	
	resp := &dto.RefreshTokensResponse{
		AccessToken: tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}
	return c.Status(200).JSON(resp)
}

func (ac *AuthController) GetCurrentUserID (c *fiber.Ctx) error {
	userID := c.Locals("userid").(uuid.UUID)

	return c.Status(200).JSON(fiber.Map{
		"userid": userID,
	})
}

func (ac *AuthController) Logout (c *fiber.Ctx) error {
	jti := c.Locals("jti").(uuid.UUID)

	if err := ac.service.Logout(c.Context(), jti); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	return c.SendStatus(204)
}