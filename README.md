# Go SAML Reverse Proxy

An authentication gateway that proxies requests to upstream services after SAML SSO or local authentication, injecting user identity headers.

## Features

- **SAML Service Provider** - Full SAML 2.0 SP implementation with IDP-initiated SSO support
- **Reverse Proxy** - Forwards SAML-authenticated requests with `X-Forwarded-User` and `X-Forwarded-Email` headers
- **Separated Authentication** - SAML for proxy access, local email/password for admin dashboard
- **Auto-provisioning** - Creates users automatically on first SAML login
- **Session Management** - Cookie-based sessions with configurable timeout
- **Structured Logging** - Logs to SQLite + stdout with automatic cleanup

## Configuration

Create `config.yaml` from the example:

```bash
cp config.yaml.example config.yaml
```

### Config Options

| Key                     | Description                       | Default                          |
| ----------------------- | --------------------------------- | -------------------------------- |
| `listen`                | Server bind address               | `:8080`                          |
| `public_url`            | External URL (for SAML callbacks) | `http://localhost:8080`          |
| `saml.idp_metadata_url` | IDP metadata endpoint             | `http://localhost:7000/metadata` |
| `saml.sp_cert`          | SP certificate file               | `sp-cert.pem`                    |
| `saml.sp_key`           | SP private key file               | `sp-key.pem`                     |
| `session.timeout`       | Session duration                  | `24h`                            |
| `upstream`              | Backend service URL               | `http://localhost:9000`          |

### Environment Variables

Override config with: `LISTEN`, `PUBLIC_URL`, `UPSTREAM_URL`, `IDP_METADATA_URL`, `SP_CERT`, `SP_KEY`, `SESSION_TIMEOUT`

## Run

### Prerequisites

- Go 1.24+
- [templ](https://templ.guide/) CLI

### Generate SP Certificates

```bash
openssl req -x509 -newkey rsa:2048 -keyout sp-key.pem -out sp-cert.pem -days 365 -nodes -subj "/CN=localhost"
```

### Build & Run

```bash
# Generate templ templates
templ generate

# Build and run
go build -o saml-proxy && ./saml-proxy
```

Server runs at http://localhost:8080

## Test

```bash
go test ./...
```

## Docker

### Build

```bash
docker build -t go-saml-proxy .
```

### Run

```bash
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/sp-cert.pem:/app/sp-cert.pem \
  -v $(pwd)/sp-key.pem:/app/sp-key.pem \
  go-saml-proxy
```

## Routes

| Route                  | Auth  | Description             |
| ---------------------- | ----- | ----------------------- |
| `GET /health`          | No    | Health check endpoint   |
| `GET /saml/metadata`   | No    | SP metadata for IDP     |
| `GET /saml/login`      | No    | Initiate SAML flow      |
| `POST /saml/acs`       | No    | SAML assertion consumer |
| `GET /saml/logout`     | No    | Single logout           |
| `GET /admin/login`     | No    | Admin login page        |
| `POST /admin/login`    | No    | Local authentication    |
| `GET /admin/register`  | No    | Registration page       |
| `POST /admin/register` | No    | Create local account    |
| `GET /admin/`          | Local | Redirects to logs       |
| `GET /admin/logs`      | Local | Admin logs dashboard    |
| `* /*`                 | SAML  | Forward to upstream     |

## Proxy Behavior

All requests (except `/admin/*`, `/saml/*`, `/health`) are forwarded to the configured upstream with:

- `X-Forwarded-User` and `X-Forwarded-Email` headers injected
- Spoofed identity headers stripped from incoming requests
- Original path preserved as-is

## Project Structure

```
├── main.go                     # Server entry point
├── config.yaml                 # Configuration file
├── backend/
│   ├── config/                 # YAML/env config loader
│   ├── database/               # SQLite connection (GORM)
│   ├── handlers/               # HTTP handlers (auth, saml, proxy, logs)
│   ├── logger/                 # Structured logging to DB
│   ├── middleware/             # Auth middleware
│   └── models/                 # User, LogEntry models
└── frontend/
    └── templates/              # templ components with Alpine.js
```
