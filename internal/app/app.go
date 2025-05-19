package app

import (
	"log/slog"
	"runtime/debug"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/superdumb33/auth-service-test/internal/config"
	"github.com/superdumb33/auth-service-test/internal/controllers"
	"github.com/superdumb33/auth-service-test/internal/infrastructure/database"
	"github.com/superdumb33/auth-service-test/internal/infrastructure/repository/pgxrepo"
	webhookclient "github.com/superdumb33/auth-service-test/internal/infrastructure/webhook_client"
	"github.com/superdumb33/auth-service-test/internal/services"
)

type App struct {
	server *fiber.App
	log    *slog.Logger
	port   string
}

func New(cfg config.AppCfg, log *slog.Logger) *App {
	pool := database.MustInitNewPool(cfg)
	authRepo := pgxrepo.NewPgxAuthRepo(pool)
	httpClient := webhookclient.MustInitNewClient(cfg.WebhookURL, log)
	authService := services.NewAuthService(authRepo, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, httpClient)
	authController := controllers.NewAuthController(authService)

	server := fiber.New(fiber.Config{
		ErrorHandler: controllers.ErrHandler,
	})
	server.Use("/", recover.New(recover.Config{
		EnableStackTrace: true,
		StackTraceHandler: func(c *fiber.Ctx, e interface{}) {
			log.Error("recovered from panic:", e,
			"stack", debug.Stack(),
	)},
	}))
	server.Use("/", controllers.LoggingHandler(log))
	apiRouter := server.Group("/api/v" + cfg.ApiVersion)
	authController.RegisterRoutes(apiRouter, controllers.AuthMiddleware(authRepo))

	return &App{server: server, log: log, port: cfg.AppPort}
}

func (app *App) Run() error {
	app.log.Info("Starting server", "port", app.port)

	return app.server.Listen(":" + app.port)
}
