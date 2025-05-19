#!/bin/bash

#db healthcheck
echo "Waiting for database to be ready"
for i in {1..60}; do
  if pg_isready -h ${POSTGRES_HOST} -p ${POSTGRES_PORT} -U ${POSTGRES_USER} > /dev/null 2>&1; then
    echo "Database is ready"
    break
  else
    echo "Waiting for database (${i}/60)"
    sleep 1
  fi
done

if [ $i -eq 60 ]; then
  echo "Database did not become ready in time. Exiting"
  exit 1
fi


#run migrations
echo "Running migrations"
migrate -path /app/migrations -database "postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=disable" up

if [ $? -ne 0 ]; then
    echo "Migrations faile!"
    exit 1
fi
echo "Migrations applied successfully"

echo "Starting application"
exec "$@"