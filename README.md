# Go SAML Reverse Proxy

An authentication gateway that proxies requests to upstream services after SAML SSO or local authentication, injecting user identity headers.

## Features

- **SAML Service Provider** - Full SAML 2.0 SP implementation
- **Reverse Proxy** - Forwards SAML-authenticated requests with `X-Forwarded-User` and `X-Forwarded-Email` headers
- **Separated Authentication** - SAML for proxy access, local email/password for admin dashboard
- **First-User Setup** - Admin registration only available for initial setup (no open registration)
- **Auto-provisioning** - Creates users automatically on first SAML login (with optional domain allowlist)
- **Session Management** - Secure cookie-based sessions with configurable timeout
- **Security Headers** - X-Frame-Options, CSP, X-Content-Type-Options, etc.
- **Rate Limiting** - Protects login/registration from brute-force attacks
- **Structured Logging** - Logs to SQLite + stdout with automatic cleanup

## Configuration

Create `config.yaml` from the example:

```bash
cp config.yaml.example config.yaml
```

### Config Options

| Key                        | Description                           | Default                          |
| -------------------------- | ------------------------------------- | -------------------------------- |
| `listen`                   | Server bind address                   | `:8080`                          |
| `public_url`               | External URL (for SAML callbacks)     | `http://localhost:8080`          |
| `database_path`            | SQLite database file path             | `app.db`                         |
| `saml.idp_metadata_url`    | IDP metadata endpoint                 | `http://localhost:7000/metadata` |
| `saml.idp_entity_id`       | Entity ID for federation metadata     | (none)                           |
| `saml.sp_cert`             | SP certificate file                   | `sp-cert.pem`                    |
| `saml.sp_key`              | SP private key file                   | `sp-key.pem`                     |
| `saml.allow_idp_initiated` | Enable IDP-initiated SSO              | `false`                          |
| `saml.allowed_domains`     | Email domains for auto-provisioning   | `[]` (all allowed)               |
| `session.timeout`          | Session duration                      | `24h`                            |
| `session.secret`           | **REQUIRED** 32+ char session secret  | (none)                           |
| `upstream`                 | Backend service URL                   | `http://localhost:9000`          |
| `upstream_skip_verify`     | Skip TLS cert verification for upstream | `false`                        |
| `tls.enabled`              | Enable TLS                            | `false`                          |
| `tls.cert`                 | TLS certificate path                  | (none)                           |
| `tls.key`                  | TLS private key path                  | (none)                           |

### Environment Variables

Override config with: `LISTEN`, `PUBLIC_URL`, `DATABASE_PATH`, `UPSTREAM_URL`, `UPSTREAM_SKIP_VERIFY`, `IDP_METADATA_URL`, `IDP_ENTITY_ID`, `SP_CERT`, `SP_KEY`, `SESSION_TIMEOUT`, `SESSION_SECRET`, `TLS_ENABLED`, `TLS_CERT`, `TLS_KEY`

### SAML Configuration

To integrate with a SAML Identity Provider (IDP), you need to exchange metadata:

**1. Get your SP metadata**

Once the proxy is running, your Service Provider metadata is available at:

```
http://localhost:8080/saml/metadata
```

Provide this URL (or download the XML) to your IDP administrator when setting up the trust relationship.

**2. Configure the IDP metadata URL**

Set `saml.idp_metadata_url` in your config to point to your IDP's metadata endpoint:

```yaml
saml:
  idp_metadata_url: https://your-idp.example.com/metadata
```

Common IDP metadata URLs:
- **Okta**: `https://{your-domain}.okta.com/app/{app-id}/sso/saml/metadata`
- **Azure AD**: `https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml`
- **Google Workspace**: `https://accounts.google.com/samlrp/metadata?rpid={app-id}`
- **OneLogin**: `https://{subdomain}.onelogin.com/saml/metadata/{app-id}`

**3. Key SAML endpoints**

| Endpoint | URL | Purpose |
| -------- | --- | ------- |
| SP Metadata | `/saml/metadata` | Give this to your IDP |
| ACS (Assertion Consumer Service) | `/saml/acs` | IDP posts SAML responses here |
| Login | `/saml/login` | Initiates SP-initiated SSO |

**4. Federation metadata (optional)**

When using federation metadata containing multiple IDPs (e.g., DFN-AAI), specify the entity ID to select a specific IDP:

```yaml
saml:
  idp_metadata_url: "http://www.aai.dfn.de/metadata/dfn-aai-local-141-metadata.xml"
  idp_entity_id: "https://idp.uni-mannheim.de/idp/shibboleth"
```

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

### Local SAML Testing

For local development, use the `saml-idp` npm package to run a mock SAML Identity Provider:

```bash
npx saml-idp --acsUrl http://localhost:8080/saml/acs --audience http://localhost:8080/saml/metadata --port 7000
```

This starts a mock IDP at http://localhost:7000 with a test login page. The default config already points to this endpoint (`saml.idp_metadata_url: http://localhost:7000/metadata`).

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
