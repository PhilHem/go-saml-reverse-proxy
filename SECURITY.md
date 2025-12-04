# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public issue for security vulnerabilities.**

Instead, please email the maintainer directly or use GitHub's private vulnerability reporting feature.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- Initial response: within 48 hours
- Status update: within 7 days
- Fix timeline: depends on severity

## Security Considerations

This project handles authentication and should be deployed with care:

- Always use HTTPS in production (`tls.enabled: true`)
- Use a strong, unique `session.secret` (32+ characters)
- Keep SAML certificates secure and rotate them periodically
- Restrict `allowed_domains` to your organization's email domains
- Review upstream service security before proxying to it

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
