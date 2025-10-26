# Structured Logging

## Overview

The OAuth server uses **zerolog** for high-performance structured logging with zero allocations. Structured logs are easier to parse, query, and analyze in production environments.

## Features

- **Structured JSON logging** for production
- **Console logging** for development
- **Request ID tracing** for distributed debugging
- **Context-aware logging** throughout the request lifecycle
- **Configurable log levels** (debug, info, warn, error, fatal, panic)
- **Automatic log sampling** to reduce high-volume debug logs
- **Zero allocation** logging for maximum performance

## Configuration

### Environment Variables

```bash
LOG_LEVEL=info           # debug|info|warn|error|fatal|panic
LOG_FORMAT=json          # json|console
LOG_CALLER=true          # Include file/line information
LOG_SAMPLING_RATE=0      # Sample 1 in N debug messages (0 = no sampling)
```

### Default Behavior

- **Development**: Console format, info level
- **Production**: JSON format, info level
- **Caller info**: Enabled by default

## Log Levels

| Level | Use Case | Example |
|-------|----------|---------|
| **debug** | Detailed debugging info | Variable values, detailed flow |
| **info** | Normal operations | Request completed, service started |
| **warn** | Unexpected but handled | Cache miss, fallback used |
| **error** | Errors needing attention | Database errors, validation failures |
| **fatal** | Unrecoverable errors | Config invalid, cannot start |
| **panic** | Critical failures | Panic recovered |

## Usage Examples

### Basic Logging

```go
logger := logging.FromContext(ctx)

// Simple messages
logger.Info("Server started")
logger.Error("Failed to process request")

// With fields
logger.InfoEvent().
    Str("user_id", userID).
    Int("status", 200).
    Dur("duration", duration).
    Msg("Request completed")
```

### Context-Aware Logging

Logs automatically include request ID when using context:

```go
// Middleware adds request ID to context
func (m *Middleware) Logger(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        requestID := logging.GenerateRequestID()
        ctx := logging.WithRequestID(r.Context(), requestID)

        requestLogger := m.logger.WithRequestID(requestID)
        ctx = logging.WithLogger(ctx, requestLogger)
        r = r.WithContext(ctx)

        // All subsequent logs will include request_id
        next.ServeHTTP(w, r)
    })
}

// In handlers/services
func (h *Handler) SomeEndpoint(w http.ResponseWriter, r *http.Request) {
    logger := logging.FromContext(r.Context())
    logger.Info("Processing request") // Automatically includes request_id
}
```

### Error Logging

```go
logger := logging.FromContext(ctx)

// With error
if err != nil {
    logger.WithError(err).Error("Database query failed")
}

// With additional fields
logger.ErrorEvent().
    Err(err).
    Str("query", query).
    Str("table", "users").
    Msg("Database operation failed")
```

### Scoped Logging

```go
// Add fields for a scope
userLogger := logger.WithUserID(userID)
userLogger.Info("User logged in")
userLogger.Info("User updated profile") // Both logs include user_id

// Add multiple fields
requestLogger := logger.WithFields(map[string]interface{}{
    "client_id": clientID,
    "grant_type": grantType,
    "scopes": scopes,
})
requestLogger.Info("Token issued")
```

## Log Output Examples

### JSON Format (Production)

```json
{
  "level": "info",
  "request_id": "req-1234-a1b2c3d4e5f6g7h8",
  "method": "POST",
  "path": "/token",
  "client_ip": "192.168.1.100",
  "status": 200,
  "duration": 45.5,
  "bytes": 1024,
  "timestamp": "2025-01-15T10:30:45.123456Z",
  "message": "request completed"
}
```

### Console Format (Development)

```
2025-01-15T10:30:45Z INF request completed
method=POST path=/token client_ip=192.168.1.100 status=200 duration=45.5ms bytes=1024
request_id=req-1234-a1b2c3d4e5f6g7h8
```

## Request ID Tracing

Every HTTP request gets a unique request ID:

1. **Generated** by middleware on request entry
2. **Added to context** for all downstream operations
3. **Included in response** via `X-Request-ID` header
4. **Logged with every event** for correlation

**Benefits**:
- Trace a single request across all logs
- Debug distributed systems
- Correlate client errors with server logs

**Example**:
```bash
# Client receives request ID in response
X-Request-ID: req-1234-a1b2c3d4e5f6g7h8

# All server logs for this request include it
grep "req-1234-a1b2c3d4e5f6g7h8" logs.json
```

## Integration with Log Aggregators

### Datadog

```json
{
  "service": "oauth-server",
  "level": "info",
  "request_id": "req-1234",
  "trace_id": "req-1234"  // Use request_id as trace_id
}
```

### Elasticsearch / Kibana

```json
POST /oauth-logs/_doc
{
  "@timestamp": "2025-01-15T10:30:45.123Z",
  "level": "info",
  "request_id": "req-1234",
  "method": "POST",
  "path": "/token"
}
```

Query example:
```
GET /oauth-logs/_search
{
  "query": {
    "match": { "request_id": "req-1234" }
  }
}
```

### CloudWatch

Logs are automatically parsed as JSON events with searchable fields.

## Performance

**Benchmarks** (from zerolog):
- **10x faster** than standard library log
- **Zero allocations** for most log operations
- **~50ns per log statement** (disabled level)
- **~300ns per log statement** (enabled with fields)

**Sampling**: Reduce log volume for high-frequency debug logs:
```bash
LOG_SAMPLING_RATE=100  # Log 1 in 100 debug messages
```

## Security

### Sensitive Data

**Never log sensitive data**:
- ❌ Passwords
- ❌ Tokens (full values)
- ❌ API keys
- ❌ Client secrets
- ❌ Personal identifiable information (PII)

**Safe logging**:
```go
// ❌ BAD
logger.Info("User password: " + password)

// ✅ GOOD
logger.Info("User authenticated successfully")

// ✅ GOOD - token hash only
logger.InfoEvent().
    Str("token_hash", hash[:8]).  // First 8 chars only
    Msg("Token validated")
```

### Query Parameter Sanitization

Middleware automatically sanitizes sensitive query parameters:
```go
// Before: ?code=abc123&password=secret
// Logged: ?code=***&password=***
```

## Migration from Standard Log

### Before

```go
log.Printf("[%s] %s %s %d %v", time, method, path, status, duration)
log.Printf("ERROR: Failed to process: %v", err)
```

### After

```go
logger.InfoEvent().
    Str("method", method).
    Str("path", path).
    Int("status", status).
    Dur("duration", duration).
    Msg("request completed")

logger.WithError(err).Error("Failed to process")
```

## Best Practices

1. **Use appropriate log levels**
   - Don't use `info` for debugging
   - Don't use `error` for expected failures

2. **Add context with fields**
   ```go
   // ✅ GOOD
   logger.InfoEvent().Str("user_id", id).Msg("User created")

   // ❌ BAD
   logger.Infof("User %s created", id)
   ```

3. **Use context-aware logging**
   ```go
   logger := logging.FromContext(ctx)  // Includes request_id automatically
   ```

4. **Keep messages concise**
   ```go
   // ✅ GOOD
   Msg("token issued")

   // ❌ BAD
   Msg("The OAuth token has been successfully issued to the client")
   ```

5. **Add structured fields, not formatted strings**
   ```go
   // ✅ GOOD
   logger.ErrorEvent().Err(err).Str("table", "users").Msg("query failed")

   // ❌ BAD
   logger.Errorf("Query failed on table users: %v", err)
   ```

## Troubleshooting

### No logs appearing

Check log level:
```bash
LOG_LEVEL=debug  # Set to debug temporarily
```

### Too many logs

Enable sampling:
```bash
LOG_SAMPLING_RATE=10  # Log 1 in 10 debug messages
```

### Can't find request logs

Search by request_id from the `X-Request-ID` response header:
```bash
grep "req-1234" logs.json
```

### Logs not structured (plain text)

Set format to JSON:
```bash
LOG_FORMAT=json
```

## References

- [zerolog GitHub](https://github.com/rs/zerolog)
- [Structured Logging Best Practices](https://www.structuredlogging.org/)
- [12-Factor App Logs](https://12factor.net/logs)
