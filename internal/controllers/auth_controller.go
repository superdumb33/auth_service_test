package controllers

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/superdumb33/auth-service-test/internal/dto"
	"github.com/superdumb33/auth-service-test/internal/entities"
	"github.com/superdumb33/auth-service-test/internal/services"
)

var (
	ErrBadRequest = entities.ErrBadRequest
)

type AuthController struct {
	service *services.AuthService
}

func NewAuthController(service *services.AuthService) *AuthController {
	return &AuthController{service: service}
}

func (ac *AuthController) RegisterRoutes(router fiber.Router, authMiddleware fiber.Handler) {
	authRouter := router.Group("/auth")
	authRouter.Post("/issue", ac.Issue)
	authRouter.Post("/refresh", ac.Refresh)

	authRouterProtected := router.Group("/auth", authMiddleware)
	authRouterProtected.Get("/me", ac.GetCurrentUserID)
	authRouterProtected.Post("/logout", ac.Logout)
}


// @Summary   Issue tokens
// @Tags      auth
// @Accept    json
// @Produce   json
// @Param     user_id   query     string  true  "User GUID"
// @Success   200       {object}  dto.IssueTokensResponse
// @Failure   400       {object}  dto.FailureResponse
// @Failure   500       {object}  dto.FailureResponse
// @Router    /auth/issue [post]
func (ac *AuthController) Issue(c *fiber.Ctx) error {
	const op = "controller:Issue"
	userID, err := uuid.Parse(c.Query("user_id"))
	if err != nil {
		return fmt.Errorf("%s:%w", op, ErrBadRequest)
	}

	userAgent := c.Get("User-Agent")
	if userAgent == "" {
		return fmt.Errorf("%s:%w", op, ErrBadRequest)
	}
	ip := c.IP()

	tokens, err := ac.service.GenerateTokens(c.Context(), userID, ip, userAgent)
	if err != nil {
		return err
	}

	resp := &dto.IssueTokensResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	return c.Status(200).JSON(resp)

}

// @Summary   Refresh tokens
// @Tags      auth
// @Accept    json
// @Produce   json
// @Param     body      body      dto.RefreshTokensRequest  true  "Access+Refresh token pair"
// @Success   200       {object}  dto.RefreshTokensResponse
// @Failure   400       {object}  dto.FailureResponse
// @Failure   401       {object}  dto.FailureResponse
// @Failure   500       {object}  dto.FailureResponse
// @Router    /auth/refresh [post]
func (ac *AuthController) Refresh(c *fiber.Ctx) error {
	const op = "controller:refresh"
	var request dto.RefreshTokensRequest
	if err := c.BodyParser(&request); err != nil {
		return fmt.Errorf("%s:%w", op, ErrBadRequest)
	}
	if request.AccessToken == "" || request.RefreshToken == "" {
		return fmt.Errorf("%s:%w", op, ErrBadRequest)
	}
	userAgent := c.Get("User-Agent")
	if userAgent == "" {
		return fmt.Errorf("%s:%w", op, ErrBadRequest)
	}

	tokens, err := ac.service.Refresh(c.Context(), request.AccessToken, request.RefreshToken, c.IP(), userAgent)
	if err != nil {
		return err
	}

	resp := &dto.RefreshTokensResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}
	return c.Status(200).JSON(resp)
}

// @Summary   Get current user
// @Tags      auth
// @Security  ApiKeyAuth
// @Produce   json
// @Success   200  {object}  dto.GetCurrentUserIDResponse
// @Failure   401  {object}  dto.FailureResponse
// @Router    /auth/me [get]
// @Security  ApiKeyAuth
func (ac *AuthController) GetCurrentUserID(c *fiber.Ctx) error {
	userID := c.Locals("userid").(uuid.UUID)

	return c.Status(200).JSON(fiber.Map{
		"user_id": userID,
	})
}

// @Summary   Logout (revoke current session)
// @Tags      auth
// @Security  ApiKeyAuth
// @Success   204
// @Failure   401  {object}  dto.FailureResponse
// @Router    /auth/logout [post]
// @Security  ApiKeyAuth
func (ac *AuthController) Logout(c *fiber.Ctx) error {
	//const op = "controller:logout"
	jti := c.Locals("jti").(uuid.UUID)

	if err := ac.service.Logout(c.Context(), jti); err != nil {
		return err
	}

	return c.SendStatus(204)
}

//can be used to revoke all tokens; for example - after password change
func (ac *AuthController) RevokeAllTokens(c *fiber.Ctx) error {
	//const op = "controller:RevokeAllTokens"
	userID := c.Locals("userid").(uuid.UUID)

	if err := ac.service.RevokeAllByUserID(c.Context(), userID); err != nil {
		return err
	}

	return c.SendStatus(204)
}
