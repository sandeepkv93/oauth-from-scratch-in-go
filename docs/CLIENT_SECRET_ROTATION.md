# Client Secret Rotation

This document describes the client secret rotation implementation in the OAuth server, which provides zero-downtime credential rotation with multi-secret support.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Usage Guide](#usage-guide)
- [Database Schema](#database-schema)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [FAQ](#faq)

## Overview

Client secret rotation is a critical security practice that involves periodically changing client credentials while maintaining service availability. This implementation provides:

- **Zero-Downtime Rotation**: Old and new secrets remain valid during grace period
- **Multi-Secret Support**: Multiple active secrets per client
- **Automatic Expiration**: Secrets expire after rotation period
- **Grace Period**: Old secrets remain valid during transition
- **Secure Storage**: bcrypt hashing for all stored secrets
- **Audit Trail**: Rotation timestamps and status tracking

## Features

### Core Functionality

1. **Secret Rotation**
   - Generate new cryptographically secure secrets
   - Mark old secrets as non-primary
   - Set expiration dates
   - Automatic cleanup of old secrets

2. **Multi-Secret Validation**
   - Support multiple active secrets simultaneously
   - Validate against all active secrets
   - Grace period for seamless transitions

3. **Secret Management**
   - Revoke secrets immediately
   - List active secrets (non-sensitive metadata only)
   - Track primary/non-primary designation
   - Monitor expiration status

4. **Auto-Rotation** (Optional)
   - Automatic rotation before expiration
   - Notification system for expiring secrets
   - Cron-compatible interface

## Architecture

### Component Structure

```
┌─────────────────────────────────────────────────────────────┐
│                     Admin API                               │
│  POST /admin/api/clients/{id}/secrets/rotate                │
│  GET  /admin/api/clients/{id}/secrets                       │
│  DELETE /admin/api/clients/{id}/secrets/{secret_id}         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                 ClientSecretManager                         │
│  • RotateSecret()         • RevokeSecret()                  │
│  • ValidateSecret()       • GetSecretInfo()                 │
│  • GetExpiringSecrets()   • AutoRotateExpiring()            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                 Database Layer                              │
│  client_secrets table                                        │
│  • id, client_id, secret_hash                               │
│  • created_at, expires_at, rotated_at, revoked_at           │
│  • is_primary, updated_at                                   │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

#### Rotation Flow
```
1. Admin initiates rotation
   ↓
2. Generate new cryptographically secure secret (32 bytes)
   ↓
3. Hash with bcrypt (cost: 10)
   ↓
4. Mark existing secrets as non-primary
   ↓
5. Create new primary secret with expiration
   ↓
6. Cleanup old secrets (keep max 2)
   ↓
7. Return plain text secret (ONLY TIME VISIBLE)
```

#### Validation Flow
```
1. Client authenticates with secret
   ↓
2. Get all active secrets for client_id
   ↓
3. Try each secret with bcrypt.CompareHashAndPassword
   ↓
4. Check expiration status
   ↓
5. Warn if using non-primary secret
   ↓
6. Return validation result
```

## Configuration

### Environment Variables

Add these variables to your `.env` file:

```bash
# Client Secret Rotation Configuration
SECRET_ROTATION_ENABLED=true           # Enable rotation feature
SECRET_MAX_ACTIVE_SECRETS=2            # Max active secrets (current + previous)
SECRET_ROTATION_PERIOD=2160h           # 90 days in hours
SECRET_GRACE_PERIOD=168h               # 7 days in hours
SECRET_AUTO_ROTATE=false               # Manual rotation by default
SECRET_NOTIFY_BEFORE_EXPIRY=336h       # 14 days in hours
```

### Configuration Struct

```go
type SecretRotationConfig struct {
    MaxActiveSecrets int           // Maximum number of active secrets per client
    RotationPeriod   time.Duration // How often secrets should be rotated
    GracePeriod      time.Duration // How long old secrets remain valid after rotation
    AutoRotate       bool          // Enable automatic rotation
    NotifyBefore     time.Duration // Notify before expiration
}
```

### Default Values

| Setting              | Default    | Description                          |
|---------------------|------------|--------------------------------------|
| Rotation Enabled    | `true`     | Feature enabled by default           |
| Max Active Secrets  | `2`        | Keep current + 1 previous            |
| Rotation Period     | `90 days`  | Secrets expire after 90 days         |
| Grace Period        | `7 days`   | Old secrets valid for 7 days         |
| Auto-Rotate         | `false`    | Manual rotation recommended          |
| Notify Before       | `14 days`  | Warn 14 days before expiration       |

## API Endpoints

### 1. Rotate Client Secret

Generates a new secret and marks the old one as non-primary.

**Endpoint:** `POST /admin/api/clients/{client_id}/secrets/rotate`

**Request:**
```bash
curl -X POST http://localhost:8080/admin/api/clients/my-client-id/secrets/rotate
```

**Response:**
```json
{
  "success": true,
  "message": "Client secret rotated successfully",
  "client_id": "my-client-id",
  "client_secret": "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4",
  "secret_id": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2026-01-23T10:00:00Z",
  "is_primary": true,
  "warning": "Save this secret immediately. It will not be shown again."
}
```

**Important:** The plain text secret is only shown once. Save it immediately!

### 2. List Active Secrets

Returns metadata about all active secrets (hashes are never returned).

**Endpoint:** `GET /admin/api/clients/{client_id}/secrets`

**Request:**
```bash
curl http://localhost:8080/admin/api/clients/my-client-id/secrets
```

**Response:**
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "active_count": 2,
  "primary_secret_id": "660e8400-e29b-41d4-a716-446655440001",
  "primary_expires_at": "2026-01-23T10:00:00Z",
  "secrets": [
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "created_at": "2025-10-25T10:00:00Z",
      "expires_at": "2026-01-23T10:00:00Z",
      "is_primary": true,
      "revoked_at": null,
      "days_until_expiry": 90,
      "is_expiring_soon": false
    },
    {
      "id": "660e8400-e29b-41d4-a716-446655440002",
      "created_at": "2025-07-27T10:00:00Z",
      "expires_at": "2025-11-01T10:00:00Z",
      "is_primary": false,
      "revoked_at": null,
      "days_until_expiry": 7,
      "is_expiring_soon": true
    }
  ]
}
```

### 3. Revoke Secret

Immediately invalidates a specific secret.

**Endpoint:** `DELETE /admin/api/clients/{client_id}/secrets/{secret_id}`

**Request:**
```bash
curl -X DELETE http://localhost:8080/admin/api/clients/my-client-id/secrets/660e8400-e29b-41d4-a716-446655440002
```

**Response:**
```json
{
  "success": true,
  "message": "Secret revoked successfully",
  "secret_id": "660e8400-e29b-41d4-a716-446655440002"
}
```

## Usage Guide

### Manual Rotation Workflow

**Recommended approach for production:**

1. **Initiate Rotation**
   ```bash
   curl -X POST http://localhost:8080/admin/api/clients/my-client-id/secrets/rotate
   ```

2. **Save New Secret**
   - Copy the `client_secret` from the response
   - Store in secure credential management system
   - Update configuration in staging environment

3. **Test in Staging**
   - Deploy new secret to staging
   - Verify OAuth flows work correctly
   - Monitor logs for authentication issues

4. **Deploy to Production**
   - Deploy new secret to production
   - Old secret remains valid during grace period (7 days)
   - Monitor for any clients still using old secret

5. **Clean Up (Optional)**
   - After grace period, old secret expires automatically
   - Or manually revoke old secret:
     ```bash
     curl -X DELETE http://localhost:8080/admin/api/clients/my-client-id/secrets/{old_secret_id}
     ```

### Automated Rotation (Advanced)

For automated rotation, enable `SECRET_AUTO_ROTATE=true` and set up a cron job:

```go
// In your application startup
secretManager := security.NewClientSecretManager(db, &security.SecretRotationConfig{
    AutoRotate:   true,
    NotifyBefore: 14 * 24 * time.Hour,
})

// Run daily cron job
func rotateExpiringSecrets() {
    count, err := secretManager.AutoRotateExpiring(context.Background())
    if err != nil {
        log.Printf("Auto-rotation failed: %v", err)
        return
    }
    log.Printf("Auto-rotated %d secrets", count)
}
```

**Warning:** Auto-rotation requires automated credential distribution to clients. Only use if you have infrastructure to push new secrets to clients automatically.

### Monitoring Expiring Secrets

```go
// Check for secrets expiring soon
expiring, err := secretManager.GetExpiringSecrets(ctx)
for _, secret := range expiring {
    log.Printf("Secret %s for client %s expires at %s",
        secret.ID, secret.ClientID, secret.ExpiresAt)

    // Send notification to administrators
    sendExpirationNotification(secret)
}
```

## Database Schema

### client_secrets Table

```sql
CREATE TABLE client_secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    secret_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    rotated_at TIMESTAMP,
    revoked_at TIMESTAMP,
    is_primary BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_client_secrets_client_id ON client_secrets(client_id);
CREATE INDEX idx_client_secrets_expires_at ON client_secrets(expires_at);
CREATE INDEX idx_client_secrets_primary ON client_secrets(client_id, is_primary)
    WHERE is_primary = true;
CREATE INDEX idx_client_secrets_active ON client_secrets(client_id)
    WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW());
```

### Migration from Legacy Schema

The migration automatically moves existing client secrets to the new table:

```sql
INSERT INTO client_secrets (client_id, secret_hash, is_primary, created_at, updated_at)
SELECT id, client_secret, true, created_at, updated_at
FROM clients
WHERE client_secret IS NOT NULL AND client_secret != '';
```

### Field Descriptions

| Field        | Type      | Description                                    |
|-------------|-----------|------------------------------------------------|
| id          | UUID      | Unique identifier for the secret               |
| client_id   | UUID      | References clients.id                          |
| secret_hash | TEXT      | bcrypt hash of the secret (never exposed)      |
| created_at  | TIMESTAMP | When the secret was created                    |
| expires_at  | TIMESTAMP | When the secret expires (NULL = never)         |
| rotated_at  | TIMESTAMP | When the secret was rotated from primary       |
| revoked_at  | TIMESTAMP | When the secret was manually revoked           |
| is_primary  | BOOLEAN   | True if this is the current primary secret     |
| updated_at  | TIMESTAMP | Last update timestamp                          |

## Security Considerations

### Cryptographic Security

1. **Random Generation**
   - Uses `crypto/rand` for cryptographically secure random bytes
   - 32 bytes of entropy per secret
   - Base64 URL encoding for safe transport

2. **Hashing**
   - bcrypt with cost factor 10
   - Resistant to rainbow table attacks
   - Automatic salt generation

3. **Secret Exposure**
   - Plain text secret only returned once at creation
   - Never stored in plain text
   - Never returned in list operations

### Operational Security

1. **Grace Period**
   - Prevents service disruption during rotation
   - Default 7 days allows ample time for deployment
   - Old and new secrets both valid during grace period

2. **Audit Trail**
   - All rotation events logged
   - Timestamps for creation, rotation, revocation
   - Track which secret was used for authentication

3. **Automatic Cleanup**
   - Old secrets automatically removed
   - Keeps only `MaxActiveSecrets` (default: 2)
   - Expired secrets no longer valid for authentication

### Best Practices

1. **Regular Rotation**
   - Rotate secrets every 90 days minimum
   - More frequently for high-security environments
   - Consider quarterly rotation cycles

2. **Secure Storage**
   - Store secrets in secure credential management systems
   - Never commit secrets to source control
   - Use environment variables or secret managers

3. **Access Control**
   - Restrict rotation API access to administrators
   - Use API authentication for rotation endpoints
   - Log all rotation operations

4. **Incident Response**
   - Revoke compromised secrets immediately
   - Generate new secret
   - Audit recent authentication attempts
   - Notify affected parties

5. **Monitoring**
   - Monitor for clients using old secrets
   - Set up alerts for expiring secrets
   - Track rotation success/failure rates

## Testing

### Unit Tests

The implementation includes comprehensive unit tests (650+ lines):

```bash
# Run all secret rotation tests
go test ./internal/security/... -v

# Run specific test
go test ./internal/security/... -run TestRotateSecret -v
```

### Test Coverage

- ✅ Secret rotation (primary/non-primary designation)
- ✅ Multi-secret validation
- ✅ Grace period support
- ✅ Secret revocation
- ✅ Expiration tracking
- ✅ Auto-rotation
- ✅ Secure random generation
- ✅ bcrypt hashing
- ✅ Secret info retrieval

### Integration Testing

Test the rotation workflow end-to-end:

```bash
# 1. Create a test client
curl -X POST http://localhost:8080/admin/api/clients \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Client", "redirect_uris": ["http://localhost:3000/callback"]}'

# 2. Rotate the secret
curl -X POST http://localhost:8080/admin/api/clients/test-client-id/secrets/rotate

# 3. Test authentication with old secret (should work during grace period)
curl -X POST http://localhost:8080/token \
  -d "grant_type=client_credentials&client_id=test-client-id&client_secret=OLD_SECRET"

# 4. Test authentication with new secret (should work)
curl -X POST http://localhost:8080/token \
  -d "grant_type=client_credentials&client_id=test-client-id&client_secret=NEW_SECRET"

# 5. List active secrets
curl http://localhost:8080/admin/api/clients/test-client-id/secrets

# 6. Revoke old secret
curl -X DELETE http://localhost:8080/admin/api/clients/test-client-id/secrets/OLD_SECRET_ID

# 7. Verify old secret no longer works
curl -X POST http://localhost:8080/token \
  -d "grant_type=client_credentials&client_id=test-client-id&client_secret=OLD_SECRET"
# Should return 401 Unauthorized
```

## FAQ

### General Questions

**Q: How does rotation affect existing OAuth flows?**

A: During the grace period, both old and new secrets work. This ensures zero-downtime rotation. Update your clients with the new secret within the grace period (default: 7 days).

**Q: What happens if I rotate while a rotation is in progress?**

A: The new rotation creates another secret. The oldest secret is automatically cleaned up based on `MaxActiveSecrets` (default: 2).

**Q: Can I have more than 2 active secrets?**

A: Yes, configure `SECRET_MAX_ACTIVE_SECRETS` to any value ≥ 1. However, 2 is recommended (current + previous) for simplicity.

**Q: What if I lose the new secret after rotation?**

A: The plain text secret is only shown once. If lost:
1. The old secret remains valid during grace period
2. You can initiate another rotation to get a new secret
3. Revoke the lost secret for security

### Security Questions

**Q: Are secrets stored in plain text?**

A: No. All secrets are hashed with bcrypt before storage. The plain text is only returned once at creation and never stored.

**Q: How long is the secret valid?**

A: Secrets expire after `RotationPeriod` (default: 90 days) from creation. Old secrets get additional `GracePeriod` (default: 7 days) after rotation.

**Q: Can a compromised secret be revoked immediately?**

A: Yes. Use the revoke endpoint to immediately invalidate any secret, even if it hasn't expired.

**Q: Is auto-rotation secure?**

A: Auto-rotation is secure but requires infrastructure to automatically distribute new secrets to clients. Only enable if you have this capability.

### Operational Questions

**Q: Should I use manual or automatic rotation?**

A: Manual rotation is recommended for most use cases. It gives you control over when rotation happens and ensures coordinated deployment. Use auto-rotation only if you have automated credential distribution.

**Q: How do I rotate secrets for multiple environments (dev, staging, prod)?**

A: Each environment should have separate client IDs and secrets. Rotate each environment independently, testing in lower environments first.

**Q: What's the performance impact of multi-secret validation?**

A: Minimal. Validation tries each active secret with bcrypt comparison. With 2 secrets, worst case is 2 bcrypt operations (~100ms). Most clients use the primary secret (first try).

**Q: Can I disable rotation?**

A: Set `SECRET_ROTATION_ENABLED=false` to disable the feature. However, regular rotation is a security best practice and is recommended.

### Troubleshooting

**Q: Client authentication fails after rotation**

A: Check:
1. Verify client is using new secret
2. Confirm old secret hasn't expired
3. Check secret wasn't revoked
4. Review auth service logs for details

**Q: How do I verify which secret a client is using?**

A: Check the logs. When a client authenticates with a non-primary secret, a warning is logged:
```
Client {client_id} authenticated with non-primary secret (rotation may be in progress)
```

**Q: Secret rotation returns error**

A: Common causes:
1. Client ID doesn't exist
2. Database connection issue
3. Permission denied
4. Check error message in response for details

## References

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [Client Authentication Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [bcrypt Algorithm](https://en.wikipedia.org/wiki/Bcrypt)

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/sandeepkv93/oauth-from-scratch-in-go/issues
- Documentation: https://github.com/sandeepkv93/oauth-from-scratch-in-go/docs/

---

**Last Updated:** October 25, 2025
**Version:** 1.0.0
