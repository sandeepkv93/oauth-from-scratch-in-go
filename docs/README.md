# OAuth 2.0 Server API Documentation

This directory contains comprehensive documentation for the OAuth 2.0 Authorization Server.

## Available Documentation

### 📋 OpenAPI Specification
- **File**: `api.yaml`
- **Description**: Complete OpenAPI 3.0 specification covering all OAuth 2.0 endpoints
- **View Online**: You can view this specification using:
  - [Swagger Editor](https://editor.swagger.io/) - Upload the YAML file
  - [Redoc](https://redocly.github.io/redoc/) - Generate beautiful documentation
  - Any OpenAPI 3.0 compatible viewer

### 🌐 Admin Interface
- **URL**: `/admin` (when server is running)
- **Description**: Web-based administration interface for managing:
  - OAuth 2.0 clients
  - Users and permissions
  - Scopes and access control
  - Server monitoring and analytics

## Quick Start Guide

### 1. View API Documentation
```bash
# Option 1: Use online Swagger Editor
# 1. Go to https://editor.swagger.io/
# 2. File > Import File > Select docs/api.yaml

# Option 2: Install and run swagger-ui locally
npm install -g swagger-ui-dist
swagger-ui-serve docs/api.yaml
```

### 2. Access Admin Interface
```bash
# Start the OAuth server
task run

# Open browser to http://localhost:8080/admin
```

### 3. Test OAuth 2.0 Flows
See the OpenAPI documentation for detailed examples of:
- Authorization Code Flow (with PKCE)
- Client Credentials Flow
- Device Authorization Flow
- Token Exchange
- And more...

## API Endpoints Overview

### Core OAuth 2.0 Endpoints
- `GET/POST /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `POST /introspect` - Token introspection (RFC 7662)
- `POST /revoke` - Token revocation (RFC 7009)

### OpenID Connect Endpoints
- `GET /userinfo` - UserInfo endpoint
- `GET/POST /logout` - End session endpoint
- `GET /.well-known/openid-configuration` - Discovery endpoint

### Dynamic Client Registration (RFC 7591)
- `POST /register` - Register new client
- `GET /register/{client_id}` - Get client configuration
- `PUT /register/{client_id}` - Update client configuration
- `DELETE /register/{client_id}` - Delete client

### Device Authorization Flow (RFC 8628)
- `POST /device_authorization` - Initiate device flow
- `GET/POST /device` - Device verification page

### Admin API
- `GET /api/clients` - List OAuth clients
- `POST /api/clients` - Create OAuth client
- `POST /api/users` - Create user account

### Discovery & Monitoring
- `GET /.well-known/oauth-authorization-server` - OAuth metadata
- `GET /.well-known/jwks.json` - JSON Web Key Set
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics

## Security Features

### Authentication & Authorization
- Multiple grant types supported
- PKCE (Proof Key for Code Exchange) support
- Scope-based authorization
- JWT token validation

### Security Headers
- CORS protection
- Rate limiting
- Request size limits
- HTTPS enforcement (configurable)
- IP blacklisting support

### Standards Compliance
- OAuth 2.0 (RFC 6749)
- OAuth 2.0 Security Best Current Practice (RFC 8252)
- PKCE (RFC 7636)
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)
- Dynamic Client Registration (RFC 7591)
- Device Authorization Grant (RFC 8628)
- JWT Bearer Token (RFC 7523)
- Token Exchange (RFC 8693)
- OpenID Connect 1.0

## Configuration

The server can be configured via environment variables or configuration files. Key configuration options include:

- **Database**: PostgreSQL connection settings
- **JWT**: Signing algorithm and secrets
- **CORS**: Allowed origins and headers
- **Rate Limiting**: Request limits and windows
- **TLS**: Certificate and key paths
- **Security**: HTTPS enforcement, IP restrictions

See the main README.md for detailed configuration instructions.

## Development

### Adding New Endpoints
1. Update the OpenAPI specification in `api.yaml`
2. Implement the handler in the appropriate service
3. Add route registration
4. Update admin interface if needed
5. Add comprehensive tests

### Updating Documentation
- The OpenAPI specification should be the single source of truth
- Update `api.yaml` when adding or modifying endpoints
- Ensure examples are accurate and helpful
- Include proper error responses and status codes

## Support

For issues, questions, or contributions:
1. Check the OpenAPI documentation for endpoint specifications
2. Use the admin interface for visual management
3. Refer to the main README.md for setup and configuration
4. Check the test files for usage examples

## License

This OAuth 2.0 server is licensed under the MIT License. See the main project README for details.