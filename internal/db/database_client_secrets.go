package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CreateClientSecret creates a new client secret
func (d *Database) CreateClientSecret(ctx context.Context, secret *ClientSecret) error {
	query := `
		INSERT INTO client_secrets (id, client_id, secret_hash, created_at, expires_at, rotated_at, revoked_at, is_primary, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at
	`

	if secret.ID == uuid.Nil {
		secret.ID = uuid.New()
	}

	if secret.CreatedAt.IsZero() {
		secret.CreatedAt = time.Now()
	}

	if secret.UpdatedAt.IsZero() {
		secret.UpdatedAt = time.Now()
	}

	err := d.db.QueryRowContext(
		ctx,
		query,
		secret.ID,
		secret.ClientID,
		secret.SecretHash,
		secret.CreatedAt,
		secret.ExpiresAt,
		secret.RotatedAt,
		secret.RevokedAt,
		secret.IsPrimary,
		secret.UpdatedAt,
	).Scan(&secret.ID, &secret.CreatedAt, &secret.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create client secret: %w", err)
	}

	return nil
}

// GetActiveClientSecrets returns all active (non-expired, non-revoked) secrets for a client
func (d *Database) GetActiveClientSecrets(ctx context.Context, clientID uuid.UUID) ([]*ClientSecret, error) {
	query := `
		SELECT id, client_id, secret_hash, created_at, expires_at, rotated_at, revoked_at, is_primary, updated_at
		FROM client_secrets
		WHERE client_id = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY is_primary DESC, created_at DESC
	`

	rows, err := d.db.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active client secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*ClientSecret
	for rows.Next() {
		secret := &ClientSecret{}
		err := rows.Scan(
			&secret.ID,
			&secret.ClientID,
			&secret.SecretHash,
			&secret.CreatedAt,
			&secret.ExpiresAt,
			&secret.RotatedAt,
			&secret.RevokedAt,
			&secret.IsPrimary,
			&secret.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan client secret: %w", err)
		}
		secrets = append(secrets, secret)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating client secrets: %w", err)
	}

	return secrets, nil
}

// GetClientSecretByID gets a specific client secret by ID
func (d *Database) GetClientSecretByID(ctx context.Context, secretID uuid.UUID) (*ClientSecret, error) {
	query := `
		SELECT id, client_id, secret_hash, created_at, expires_at, rotated_at, revoked_at, is_primary, updated_at
		FROM client_secrets
		WHERE id = $1
	`

	secret := &ClientSecret{}
	err := d.db.QueryRowContext(ctx, query, secretID).Scan(
		&secret.ID,
		&secret.ClientID,
		&secret.SecretHash,
		&secret.CreatedAt,
		&secret.ExpiresAt,
		&secret.RotatedAt,
		&secret.RevokedAt,
		&secret.IsPrimary,
		&secret.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("client secret not found: %s", secretID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get client secret: %w", err)
	}

	return secret, nil
}

// MarkSecretsNonPrimary marks all secrets for a client as non-primary
func (d *Database) MarkSecretsNonPrimary(ctx context.Context, clientID uuid.UUID) error {
	query := `
		UPDATE client_secrets
		SET is_primary = false,
		    rotated_at = CASE WHEN is_primary = true THEN NOW() ELSE rotated_at END,
		    updated_at = NOW()
		WHERE client_id = $1
		  AND revoked_at IS NULL
	`

	_, err := d.db.ExecContext(ctx, query, clientID)
	if err != nil {
		return fmt.Errorf("failed to mark secrets as non-primary: %w", err)
	}

	return nil
}

// RevokeClientSecret revokes a specific client secret
func (d *Database) RevokeClientSecret(ctx context.Context, secretID uuid.UUID) error {
	query := `
		UPDATE client_secrets
		SET revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
		  AND revoked_at IS NULL
	`

	result, err := d.db.ExecContext(ctx, query, secretID)
	if err != nil {
		return fmt.Errorf("failed to revoke client secret: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("client secret not found or already revoked: %s", secretID)
	}

	return nil
}

// CleanupOldSecrets removes old secrets keeping only the most recent maxSecrets
func (d *Database) CleanupOldSecrets(ctx context.Context, clientID uuid.UUID, maxSecrets int) error {
	// This query keeps the most recent maxSecrets secrets (by created_at)
	// and deletes the rest
	query := `
		DELETE FROM client_secrets
		WHERE id IN (
			SELECT id
			FROM client_secrets
			WHERE client_id = $1
			ORDER BY created_at DESC
			OFFSET $2
		)
	`

	_, err := d.db.ExecContext(ctx, query, clientID, maxSecrets)
	if err != nil {
		return fmt.Errorf("failed to cleanup old secrets: %w", err)
	}

	return nil
}

// GetExpiringSecrets returns secrets that will expire within the given duration
func (d *Database) GetExpiringSecrets(ctx context.Context, withinDuration time.Duration) ([]*ClientSecret, error) {
	query := `
		SELECT id, client_id, secret_hash, created_at, expires_at, rotated_at, revoked_at, is_primary, updated_at
		FROM client_secrets
		WHERE revoked_at IS NULL
		  AND expires_at IS NOT NULL
		  AND expires_at > NOW()
		  AND expires_at <= NOW() + $1::interval
		ORDER BY expires_at ASC
	`

	// Convert duration to PostgreSQL interval format
	interval := fmt.Sprintf("%d seconds", int(withinDuration.Seconds()))

	rows, err := d.db.QueryContext(ctx, query, interval)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*ClientSecret
	for rows.Next() {
		secret := &ClientSecret{}
		err := rows.Scan(
			&secret.ID,
			&secret.ClientID,
			&secret.SecretHash,
			&secret.CreatedAt,
			&secret.ExpiresAt,
			&secret.RotatedAt,
			&secret.RevokedAt,
			&secret.IsPrimary,
			&secret.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan expiring secret: %w", err)
		}
		secrets = append(secrets, secret)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating expiring secrets: %w", err)
	}

	return secrets, nil
}

// Transaction implementation - wrap the database methods
func (tx *DatabaseTransaction) CreateClientSecret(ctx context.Context, secret *ClientSecret) error {
	query := `
		INSERT INTO client_secrets (id, client_id, secret_hash, created_at, expires_at, rotated_at, revoked_at, is_primary, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at
	`

	if secret.ID == uuid.Nil {
		secret.ID = uuid.New()
	}

	if secret.CreatedAt.IsZero() {
		secret.CreatedAt = time.Now()
	}

	if secret.UpdatedAt.IsZero() {
		secret.UpdatedAt = time.Now()
	}

	err := tx.tx.QueryRowContext(
		ctx,
		query,
		secret.ID,
		secret.ClientID,
		secret.SecretHash,
		secret.CreatedAt,
		secret.ExpiresAt,
		secret.RotatedAt,
		secret.RevokedAt,
		secret.IsPrimary,
		secret.UpdatedAt,
	).Scan(&secret.ID, &secret.CreatedAt, &secret.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create client secret in transaction: %w", err)
	}

	return nil
}

func (tx *DatabaseTransaction) GetActiveClientSecrets(ctx context.Context, clientID uuid.UUID) ([]*ClientSecret, error) {
	query := `
		SELECT id, client_id, secret_hash, created_at, expires_at, rotated_at, revoked_at, is_primary, updated_at
		FROM client_secrets
		WHERE client_id = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY is_primary DESC, created_at DESC
	`

	rows, err := tx.tx.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active client secrets in transaction: %w", err)
	}
	defer rows.Close()

	var secrets []*ClientSecret
	for rows.Next() {
		secret := &ClientSecret{}
		err := rows.Scan(
			&secret.ID,
			&secret.ClientID,
			&secret.SecretHash,
			&secret.CreatedAt,
			&secret.ExpiresAt,
			&secret.RotatedAt,
			&secret.RevokedAt,
			&secret.IsPrimary,
			&secret.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan client secret in transaction: %w", err)
		}
		secrets = append(secrets, secret)
	}

	return secrets, rows.Err()
}

func (tx *DatabaseTransaction) GetClientSecretByID(ctx context.Context, secretID uuid.UUID) (*ClientSecret, error) {
	query := `
		SELECT id, client_id, secret_hash, created_at, expires_at, rotated_at, revoked_at, is_primary, updated_at
		FROM client_secrets
		WHERE id = $1
	`

	secret := &ClientSecret{}
	err := tx.tx.QueryRowContext(ctx, query, secretID).Scan(
		&secret.ID,
		&secret.ClientID,
		&secret.SecretHash,
		&secret.CreatedAt,
		&secret.ExpiresAt,
		&secret.RotatedAt,
		&secret.RevokedAt,
		&secret.IsPrimary,
		&secret.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("client secret not found: %s", secretID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get client secret in transaction: %w", err)
	}

	return secret, nil
}

func (tx *DatabaseTransaction) MarkSecretsNonPrimary(ctx context.Context, clientID uuid.UUID) error {
	query := `
		UPDATE client_secrets
		SET is_primary = false,
		    rotated_at = CASE WHEN is_primary = true THEN NOW() ELSE rotated_at END,
		    updated_at = NOW()
		WHERE client_id = $1
		  AND revoked_at IS NULL
	`

	_, err := tx.tx.ExecContext(ctx, query, clientID)
	if err != nil {
		return fmt.Errorf("failed to mark secrets as non-primary in transaction: %w", err)
	}

	return nil
}

func (tx *DatabaseTransaction) RevokeClientSecret(ctx context.Context, secretID uuid.UUID) error {
	query := `
		UPDATE client_secrets
		SET revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
		  AND revoked_at IS NULL
	`

	result, err := tx.tx.ExecContext(ctx, query, secretID)
	if err != nil {
		return fmt.Errorf("failed to revoke client secret in transaction: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected in transaction: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("client secret not found or already revoked: %s", secretID)
	}

	return nil
}

func (tx *DatabaseTransaction) CleanupOldSecrets(ctx context.Context, clientID uuid.UUID, maxSecrets int) error {
	query := `
		DELETE FROM client_secrets
		WHERE id IN (
			SELECT id
			FROM client_secrets
			WHERE client_id = $1
			ORDER BY created_at DESC
			OFFSET $2
		)
	`

	_, err := tx.tx.ExecContext(ctx, query, clientID, maxSecrets)
	if err != nil {
		return fmt.Errorf("failed to cleanup old secrets in transaction: %w", err)
	}

	return nil
}

func (tx *DatabaseTransaction) GetExpiringSecrets(ctx context.Context, withinDuration time.Duration) ([]*ClientSecret, error) {
	query := `
		SELECT id, client_id, secret_hash, created_at, expires_at, rotated_at, revoked_at, is_primary, updated_at
		FROM client_secrets
		WHERE revoked_at IS NULL
		  AND expires_at IS NOT NULL
		  AND expires_at > NOW()
		  AND expires_at <= NOW() + $1::interval
		ORDER BY expires_at ASC
	`

	interval := fmt.Sprintf("%d seconds", int(withinDuration.Seconds()))

	rows, err := tx.tx.QueryContext(ctx, query, interval)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring secrets in transaction: %w", err)
	}
	defer rows.Close()

	var secrets []*ClientSecret
	for rows.Next() {
		secret := &ClientSecret{}
		err := rows.Scan(
			&secret.ID,
			&secret.ClientID,
			&secret.SecretHash,
			&secret.CreatedAt,
			&secret.ExpiresAt,
			&secret.RotatedAt,
			&secret.RevokedAt,
			&secret.IsPrimary,
			&secret.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan expiring secret in transaction: %w", err)
		}
		secrets = append(secrets, secret)
	}

	return secrets, rows.Err()
}
