# OAuth 2.0 Server Implementation in Go

A production-ready OAuth 2.0 authorization server implementation built from scratch in Go, following RFC 6749 and OAuth 2.0 Security Best Practices.

## Features

- **OAuth 2.0 Grant Types**:
  - Authorization Code Grant
  - Client Credentials Grant  
  - Refresh Token Grant
- **JWT Access Tokens** with configurable expiration
- **Secure Client Authentication** with bcrypt password hashing
- **Scope-based Authorization** with RBAC support
- **Rate Limiting** for security and abuse prevention
- **PostgreSQL Database** integration with connection pooling
- **Comprehensive Security Headers** and CORS support
- **Docker Support** for easy deployment
- **Health Checks** and monitoring endpoints
- **Well-known Configuration** endpoint (RFC 8414)
- **Token Introspection** endpoint (RFC 7662)
- **Structured Logging** and error handling

## Architecture

```
├── cmd/server/          # Main application entry point
├── internal/
│   ├── auth/           # OAuth 2.0 authentication logic
│   ├── client/         # Client management
│   ├── config/         # Configuration management
│   ├── db/             # Database models and operations
│   ├── handlers/       # HTTP handlers for OAuth endpoints
│   ├── middleware/     # HTTP middleware (logging, CORS, rate limiting)
│   ├── scope/          # Scope validation and management
│   └── token/          # Token generation and validation
├── pkg/
│   ├── jwt/            # JWT token utilities
│   ├── crypto/         # Cryptographic utilities
│   └── utils/          # Common utilities
├── scripts/            # Database setup and testing scripts
├── tests/              # Unit and integration tests
└── web/                # Static files and templates
```

## Prerequisites

- Go 1.24+
- PostgreSQL 12+
- Git
- Task (for build automation)

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd oauth-from-scratch-in-go
   ```

2. **Install Task**:
   ```bash
   # Install Task
   sh -c "$(curl -ssL https://taskfile.dev/install.sh)"
   # OR use the project's self-install
   task install:taskfile
   ```

3. **Install dependencies**:
   ```bash
   task deps
   ```

4. **Setup environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Setup database**:
   ```bash
   # Create PostgreSQL database
   createdb oauth_server
   
   # Run setup script
   task db:setup
   ```

6. **Build and run**:
   ```bash
   task build && task run
   
   # Quick development run (no build step)
   task run:dev
   ```

The server will start on `http://localhost:8080`

### Development Commands

```bash
# View all available tasks
task --list

# Development workflow
task run:dev           # Run with hot reload
task run:watch         # Run with file watching (requires air)
task test              # Run all tests
task test:unit         # Run unit tests only
task test:coverage     # Run tests with coverage report
task fmt               # Format code
task lint              # Run linter
task check             # Run all checks (fmt, lint, security, test)

# Database operations
task db:setup          # Setup database
task db:migrate        # Run migrations
task db:reset          # Reset database

# Git operations
task git:hooks:install # Install git hooks
task git:tag:create TAG=v1.0.0  # Create and push tag

# Kubernetes deployment
task k8s:deploy        # Deploy to Kubernetes
task k8s:status        # Check deployment status
task k8s:logs          # View application logs

# Build for multiple platforms
task release           # Build release binaries
```

### Docker Deployment

1. **Build Docker image**:
   ```bash
   task docker:build
   ```

2. **Run with Docker**:
   ```bash
   task docker:run
   
   # Run with environment file
   task docker:run:env
   ```

## OAuth 2.0 Flows

### Authorization Code Flow

1. **Authorization Request**:
   ```
   GET /authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&scope=SCOPE&state=STATE
   ```

2. **User Authentication**: User logs in through the authorization page

3. **Authorization Grant**: Server redirects to `REDIRECT_URI` with authorization code

4. **Token Exchange**:
   ```bash
   curl -X POST http://localhost:8080/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=REDIRECT_URI&client_id=CLIENT_ID&client_secret=CLIENT_SECRET"
   ```

### Client Credentials Flow

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&scope=SCOPE"
```

### Refresh Token Flow

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=CLIENT_ID&client_secret=CLIENT_SECRET"
```

## API Endpoints

### OAuth 2.0 Endpoints

- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint  
- `POST /introspect` - Token introspection
- `GET /userinfo` - User information (OpenID Connect)
- `GET /.well-known/oauth-authorization-server` - Server metadata

### Management API

- `POST /api/clients` - Create OAuth client
- `GET /api/clients` - List OAuth clients
- `POST /api/users` - Create user account

### System Endpoints

- `GET /health` - Health check
- `GET /login` - User login page

## Configuration

The server can be configured using environment variables or a `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Server bind address | `localhost` |
| `SERVER_PORT` | Server port | `8080` |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | Database user | `postgres` |
| `DB_PASSWORD` | Database password | |
| `DB_NAME` | Database name | `oauth_server` |
| `JWT_SECRET` | JWT signing secret | |
| `ACCESS_TOKEN_TTL` | Access token lifetime | `15m` |
| `REFRESH_TOKEN_TTL` | Refresh token lifetime | `168h` |
| `RATE_LIMIT_REQUESTS` | Rate limit per window | `100` |
| `RATE_LIMIT_WINDOW` | Rate limit window | `1m` |

## Testing

### Run Unit Tests

```bash
task test
```

### Run with Coverage

```bash
task test:coverage
```

### Test OAuth Flows

```bash
task test:oauth
```

This will run a comprehensive test script that demonstrates all OAuth flows.

## Security Features

- **Secure Password Hashing**: bcrypt with configurable cost
- **JWT Token Security**: HMAC-SHA256 signed tokens
- **Rate Limiting**: Configurable per-IP rate limiting
- **Input Validation**: Comprehensive request validation
- **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
- **CORS Protection**: Configurable allowed origins
- **SQL Injection Protection**: Parameterized queries
- **Timing Attack Protection**: Constant-time comparisons

## Development

### Available Task Commands

```bash
task --list            # Show all available tasks
task deps              # Install dependencies
task build             # Build the server
task run               # Run the server
task test              # Run tests
task fmt               # Format code
task lint              # Lint code
task security          # Security scan
task run:dev           # Development server
task install:tools     # Install development tools
```

### Code Structure

- **Clean Architecture**: Separation of concerns with clear layers
- **Dependency Injection**: Testable and maintainable code
- **Error Handling**: Comprehensive error types and handling
- **Logging**: Structured logging throughout the application
- **Testing**: Unit tests with mocks and integration tests

## Production Deployment

### Security Checklist

- [ ] Set strong `JWT_SECRET` (minimum 32 characters)
- [ ] Use HTTPS in production
- [ ] Configure proper `ALLOWED_ORIGINS`
- [ ] Set up database connection pooling
- [ ] Enable PostgreSQL SSL mode
- [ ] Configure firewall rules
- [ ] Set up monitoring and logging
- [ ] Regular security updates
- [ ] Backup strategy for database

### Environment Variables for Production

```bash
# Use strong, random secrets
JWT_SECRET=your-very-secure-secret-key-at-least-32-chars
DB_PASSWORD=secure-database-password
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Enable SSL for database
DB_SSL_MODE=require

# Adjust rate limiting for production load
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=1m
```

## Standards Compliance

This implementation follows these RFCs and standards:

- **RFC 6749**: The OAuth 2.0 Authorization Framework
- **RFC 6750**: The OAuth 2.0 Authorization Framework: Bearer Token Usage
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7636**: Proof Key for Code Exchange by OAuth Public Clients (PKCE)
- **RFC 7662**: OAuth 2.0 Token Introspection
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata
- **OpenID Connect Core 1.0**: Authentication layer on top of OAuth 2.0

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## Support

For issues and questions:
- Check the documentation
- Review existing issues
- Create a new issue with detailed information

---

**Note**: This is a reference implementation for educational purposes. For production use, conduct a thorough security review and consider using established OAuth providers for critical applications.