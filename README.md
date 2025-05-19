# RESTful API auth service

## Endpoints

- `POST /api/v1/users/authorize` — generate a new pair of tokens for a given user UUID.
- `POST /api/v1/users/refresh`   — refresh both access and refresh tokens, with IP-change warning via email.

---

## Prerequisites

- Go **1.20+**
- Docker and Docker Compose

---

## Getting Started

1. **Clone the repo**
   ```bash
   git clone https://github.com/your-org/your-repo.git
   cd your-repo
   ```
   
2. **Copy environment file**
   ```bash
   cp .env.example .env
   ```

3. **Start Docker services**
   ```bash
   docker-compose up --build
   ```
   
   **Line Ending Notice**
   
   Please pay attention that after cloning the repo, entrypoint.sh script may have DOS (CRLF) line endings, and Docker can only interprete Unix (LF) line endings
   
   **Quick fix**
   ```bash
   # dos2unix (if installed)
   dos2unix entrypoint.sh

   # with sed (no extra dependencies)
   sed -i 's/\r$//' entrypoint.sh
   ```
   
  
   The service listens on **localhost:3000** by default.

---

## Configuration

Example `.env.example`:

```dotenv
#postgres-db
POSTGRES_USER=postgres
POSTGRES_DB=test_db
POSTGRES_PASSWORD=super_secret
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

#app
JWT_SECRET=ISKML-PJQAT-WDCYB-XOHRU

#smtp-server
SMTP_FROM=noreply@rest.service
SMTP_HOST=mailpit
SMTP_PORT=1025
SMTP_USERNAME=
SMTP_PASSWORD=
```

---

## API Endpoints

### `POST /api/v1/users/authorize`
Generate a new access + refresh token pair for a user.

- **URL:** `/api/v1/users/authorize`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Body:**
  ```json
  {
    "uuid": "<user-uuid>"
  }
  ```
- **Response (200):**
  ```json
  {
    "access_token":  "<jwt_access_token>",
    "refresh_token": "<base64_refresh_token>"
  }
  ```

### `POST /api/v1/users/refresh`
Refresh both tokens. If the request IP differs from the one embedded in the refresh token, a warning email is sent.

- **URL:** `/api/v1/users/refresh`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Body:**
  ```json
  {
    "access_token":  "<jwt_access_token>",
    "refresh_token": "<base64_refresh_token>"
  }
  ```
- **Response (200):**
  ```json
  {
    "access_token":  "<jwt_access_token>",
    "refresh_token": "<base64_refresh_token>"
  }
---

## Examples (cURL)

**Authorize**
```bash
curl -X POST http://localhost:3000/api/v1/users/authorize \
  -H "Content-Type: application/json" \
  -d '{"uuid":"e98bcb0e-de7c-4440-8b96-e21f616cc3ba"}'
```

**Refresh**
```bash
curl -X POST http://localhost:3000/api/v1/users/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "access_token":"<YOUR_ACCESS_TOKEN>",
    "refresh_token":"<YOUR_REFRESH_TOKEN>"
  }'
```

---

## Running Tests

Unit tests covers service logic (like generation and validation) and repository interactions. To run:

**Notice, that repository tests using test database connection, so in order to run repository tests you have to run test database docker container**
```bash
docker compose up -d test_postgres
```

**All tests:**
```bash
go test -v ./...
```
**Auth service tests::**
```bash
go test -v ./internal/services
```
**Auth repository tests:**
```bash
go test -v ./internal/infrastructure/repository/pgxrepo/
```
---

