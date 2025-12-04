# Contributing to go-saml-reverse-proxy

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/go-saml-reverse-proxy.git`
3. Create a branch: `git checkout -b feature/your-feature-name`

## Development Setup

### Prerequisites

- Go 1.24 or later
- [templ](https://templ.guide/) CLI for template generation

### Building

```bash
# Generate templates
templ generate

# Build the binary
go build -o saml-proxy .
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with race detection and coverage
go test ./... -race -cover
```

## Submitting Changes

1. Ensure all tests pass
2. Update documentation if needed
3. Commit your changes with a clear commit message
4. Push to your fork
5. Open a Pull Request

## Code Style

- Follow standard Go conventions and `go fmt`
- Keep functions focused and testable
- Add tests for new functionality

## Reporting Bugs

Please open an issue with:
- A clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Go version and OS

## Questions?

Open an issue for any questions about contributing.
