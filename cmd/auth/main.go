package main

import (
	"log/slog"
	"os"

	"github.com/superdumb33/auth-service-test/internal/app"
	"github.com/superdumb33/auth-service-test/internal/config"
)

func main() {
	cfg := config.MustInit()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	app := app.New(cfg, log)

	app.Run()
}