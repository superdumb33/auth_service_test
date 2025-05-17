package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

type AppCfg struct {
	PostgresUser     string
	PostgresDB       string
	PostgresPassword string
	PostgresHost     string
	PostgresPort     string
	JWTSecret        string
	AppPort          string
	ApiVersion       string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
}

// it'll throw a panic if something goes wrong
func MustInit() AppCfg {
	//.Load() should be called if the app is being launched with `go run`; docker compose will launch service with env variables set from provided .env file
	godotenv.Load(".env")
	accessTTL, err := time.ParseDuration(os.Getenv("ACCESS_TOKEN_TTL"))
	if err != nil {
		panic(err)
	}
	refreshTTL, err := time.ParseDuration(os.Getenv("REFRESH_TOKEN_TTL"))
	if err != nil {
		panic(err)
	}

	return AppCfg{
		PostgresUser:     os.Getenv("POSTGRES_USER"),
		PostgresDB:       os.Getenv("POSTGRES_DB"),
		PostgresPassword: os.Getenv("POSTGRES_PASSWORD"),
		PostgresHost:     os.Getenv("POSTGRES_HOST"),
		PostgresPort:     os.Getenv("POSTGRES_PORT"),
		JWTSecret:        os.Getenv("JWT_SECRET"),
		AppPort:          os.Getenv("APP_PORT"),
		ApiVersion:       os.Getenv("API_VERSION"),
		AccessTokenTTL:   accessTTL,
		RefreshTokenTTL:  refreshTTL,
	}
}
