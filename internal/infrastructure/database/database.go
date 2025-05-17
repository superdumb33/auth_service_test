package database

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superdumb33/auth-service-test/internal/config"
)

//it'll throw a panic if error happens
func MustInitNewPool(cfg config.AppCfg) *pgxpool.Pool {
	dsn :="host=" + cfg.PostgresHost + 
	" user=" + cfg.PostgresUser + 
	" password=" + cfg.PostgresPassword + 
	" dbname=" + cfg.PostgresDB + 
	" port=" + cfg.PostgresPort

	pool, err := pgxpool.New(context.Background(), dsn) 
	if err != nil {
		panic(err)
	}

	return pool
}