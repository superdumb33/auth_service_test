package controllers

import (
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
)

func LoggingHandler(log *slog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		err := c.Next()
		if err != nil {
		log.Error("HTTP request results",
			"method", c.Method(),
			"path", c.Path(),
			"ip", c.IP(),
			"ua", c.Get("User-Agent"),
			"latency", time.Since(start),
			"error", err.Error(),
		)
		
		return err
		}

		log.Info("HTTP request results",
			"method", c.Method(),
			"path", c.Path(),
			"ip", c.IP(),
			"ua", c.Get("User-Agent"),
			"latency", time.Since(start),
		)

		return nil
	}
}
