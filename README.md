# RESTful API Auth Service

Authentication service using access/refresh token pair with IP/User-Agent validation and revocation logic.

---

## Endpoints

- `POST /api/v1/auth/issue` — generate a new access/refresh token pair for a user.
- `POST /api/v1/auth/refresh` — refresh tokens (revokes on User-Agent mismatch, warns on IP change).
- `GET /api/v1/auth/me` — get current user ID (requires Authorization header).
- `POST /api/v1/auth/logout` — revoke current session (logout).

---

## Prerequisites

- Go 1.20+
- Docker + Docker Compose

---

## Getting Started

1. **Clone the repo**
   
  ```bash
  git clone https://github.com/superdumb33/auth_service_test.git
  cd auth_service_test
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
APP_PORT=3000
API_VERSION=1
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=1h
WEBHOOK_URL=https://httpstat.us/200
```

---
## API Reference

### POST /api/v1/auth/issue

Generate a new access + refresh token pair for a user.

- **Query Param**:
  - `user_id` (UUID, required)

**Example**:

```bash
curl -X POST "http://localhost:3000/api/v1/auth/issue?user_id=<UUID>"
```

**Response (200 OK)**:

```json
{
  "access_token":  "<jwt_access_token>",
  "refresh_token": "<base64_refresh_token>"
}
```

---

### POST /api/v1/auth/refresh

Refresh access and refresh tokens.

- Requires:
  - `access_token`: previously issued JWT (can be expired)
  - `refresh_token`: base64 string
  - User-Agent must match the original

- If IP differs from the original — a webhook is triggered.
- If User-Agent mismatches — session is revoked and 401 returned.

**Example**:

```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh   -H "Content-Type: application/json"   -H "User-Agent: my-browser"   -d '{
    "access_token": "<jwt_token>",
    "refresh_token": "<refresh_token>"
  }'
```

**Response (200 OK)**:

```json
{
  "access_token":  "<jwt_access_token>",
  "refresh_token": "<base64_refresh_token>"
}
```

---

### GET /api/v1/auth/me

Get the UUID of the currently authenticated user.

- Requires Authorization header with valid (non-expired) access token.

**Example**:

```bash
curl -X GET http://localhost:3000/api/v1/auth/me   -H "Authorization: Bearer <jwt_token>"
```

**Response (200 OK)**:

```json
{
  "user_id": "<uuid>"
}
```

---

### POST /api/v1/auth/logout

Revoke the current session. Requires Authorization header.

**Example**:

```bash
curl -X POST http://localhost:3000/api/v1/auth/logout   -H "Authorization: Bearer <jwt_token>"
```

**Response (204 No Content)**

---

## Running Tests

```bash
go test -v ./...
```
---
