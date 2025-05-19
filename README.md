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

Clone the repository:

```bash
git clone https://github.com/superdumb33/auth_service_test.git
cd auth_service_test
```

Start the service:

```bash
docker-compose up --build
```

Swagger UI available at:  
`http://localhost:3000/swagger/index.html`

Default app port: `3000`.

---

## Line Ending Notice 

If `entrypoint.sh` has Windows line endings (CRLF), Docker may fail to execute it. To fix:

```bash
# dos2unix (if available)
dos2unix entrypoint.sh

# or with sed (no dependencies)
sed -i 's/
$//' entrypoint.sh
```

---

## Environment Configuration

`.env.example` :

```env
# postgres
POSTGRES_USER=postgres
POSTGRES_DB=test_db
POSTGRES_PASSWORD=super_secret
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

# app
JWT_SECRET=ISKML-PJQAT-WDCYB-XOHRU
APP_PORT=3000
API_VERSION=1
ACCESS_TOKEN_TTL=1m
REFRESH_TOKEN_TTL=1h
WEBHOOK_URL=https://httpstat.us/200
```

---

## API Examples (cURL)

### Issue token pair

```bash
curl -X POST "http://localhost:3000/api/v1/auth/issue?user_id=<USER_UUID>"
```

Response:

```json
{
  "access_token": "<jwt_token>",
  "refresh_token": "<refresh_token_base64>"
}
```

### Refresh token pair

```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh   -H "Content-Type: application/json"   -H "User-Agent: <same-agent>"   -d '{
    "access_token": "<jwt_token>",
    "refresh_token": "<refresh_token>"
  }'
```

### Get current user

```bash
curl -X GET http://localhost:3000/api/v1/auth/me   -H "Authorization: Bearer <access_token>"
```

### Logout

```bash
curl -X POST http://localhost:3000/api/v1/auth/logout   -H "Authorization: Bearer <access_token>"
```

---

## Running Tests

```bash
go test -v ./...
```
---
