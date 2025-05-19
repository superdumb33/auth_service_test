package controllers

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/superdumb33/auth-service-test/internal/entities"
)

//maps error to HTTP code by comapring err with a sentinel entities package errors, 
func ErrHandler(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, entities.ErrBadRequest):
		return c.Status(http.StatusBadRequest).
			JSON(fiber.Map{"error": http.StatusText(http.StatusBadRequest)})
	case errors.Is(err, entities.ErrNotFound):
		return c.Status(http.StatusNotFound).
			JSON(fiber.Map{"error": http.StatusText(http.StatusNotFound)})
	case errors.Is(err, entities.ErrDuplicate):
		return c.Status(http.StatusConflict).
			JSON(fiber.Map{"error": http.StatusText(http.StatusConflict)})
	case errors.Is(err, entities.ErrExpired):
		return c.Status(http.StatusUnauthorized).
			JSON(fiber.Map{"error": http.StatusText(http.StatusUnauthorized)})
	case errors.Is(err, entities.ErrUnauthorized):
		return c.Status(http.StatusUnauthorized).
			JSON(fiber.Map{"error": http.StatusText(http.StatusUnauthorized)})
	default:
		return c.Status(http.StatusInternalServerError).
			JSON(fiber.Map{"error": http.StatusText(http.StatusInternalServerError)})
	}
}
