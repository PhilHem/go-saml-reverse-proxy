# Stage 1: Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Install templ
RUN go install github.com/a-h/templ/cmd/templ@latest

# Cache deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source & build
COPY . .
RUN templ generate
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o saml-proxy

# Stage 2: Minimal runtime
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/saml-proxy .

EXPOSE 8080
CMD ["./saml-proxy"]

