package app

// @title           Auth Service API
// @version         1.0
// @description     auth service.
// @host            localhost:3000
// @BasePath        /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

import (
	"log/slog"
	"runtime/debug"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	_ "github.com/superdumb33/auth-service-test/docs"
	"github.com/superdumb33/auth-service-test/internal/config"
	"github.com/superdumb33/auth-service-test/internal/controllers"
	"github.com/superdumb33/auth-service-test/internal/infrastructure/database"
	"github.com/superdumb33/auth-service-test/internal/infrastructure/repository/pgxrepo"
	webhookclient "github.com/superdumb33/auth-service-test/internal/infrastructure/webhook_client"
	"github.com/superdumb33/auth-service-test/internal/services"
	fiberSwagger "github.com/swaggo/fiber-swagger"
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
	server.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))
	server.Get("/swagger/*", fiberSwagger.WrapHandler)
	server.Use(recover.New(recover.Config{
		EnableStackTrace: true,
		StackTraceHandler: func(c *fiber.Ctx, e interface{}) {
			log.Error("recovered from panic:", e,
				"stack", debug.Stack(),
			)
		},
	}))
	server.Use(controllers.LoggingHandler(log))
	apiRouter := server.Group("/api/v" + cfg.ApiVersion)
	authController.RegisterRoutes(apiRouter, controllers.AuthMiddleware(authRepo))

	return &App{server: server, log: log, port: cfg.AppPort}
}

func (app *App) Run() error {
	app.log.Info("Starting server", "port", app.port)

	return app.server.Listen(":" + app.port)
}
