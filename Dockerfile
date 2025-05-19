FROM golang:1.24-bullseye AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod tidy

COPY . .

RUN apt-get update && apt-get install -y postgresql-client \
  && go build -o /app/cmd/auth/main ./cmd/auth \
  && go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest \
  && ln -s /go/bin/migrate /usr/local/bin/migrate

COPY migrations/ /app/migrations/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/cmd/auth/main"]