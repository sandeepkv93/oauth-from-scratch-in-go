# OAuth 2.0 Server Production Deployment Guide

This comprehensive guide covers deploying the OAuth 2.0 server to production environments with enterprise-grade security, monitoring, and high availability.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Database Setup](#database-setup)
4. [Security Configuration](#security-configuration)
5. [Docker Deployment](#docker-deployment)
6. [Kubernetes Deployment](#kubernetes-deployment)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Load Balancing and Scaling](#load-balancing-and-scaling)
9. [Backup and Recovery](#backup-and-recovery)
10. [Security Hardening](#security-hardening)
11. [Performance Optimization](#performance-optimization)
12. [Troubleshooting](#troubleshooting)

## Prerequisites

### Infrastructure Requirements

- **Kubernetes Cluster**: v1.20+ with at least 3 nodes
- **PostgreSQL Database**: v12+ (managed service recommended)
- **Load Balancer**: NGINX Ingress Controller or cloud provider LB
- **Certificate Management**: cert-manager for TLS certificates
- **Monitoring Stack**: Prometheus, Grafana, AlertManager
- **Storage**: Persistent volumes for database

### Tools Required

```bash
# Container tools
docker --version          # 20.10+
kubectl version --client  # 1.20+

# Kubernetes tools
helm version              # 3.7+
kustomize version         # 4.0+

# Database tools
psql --version           # 12+

# Security tools
openssl version          # 1.1+
```

## Environment Setup

### 1. Environment Variables

Create production environment configuration:

```bash
# Create production environment file
cat > .env.production << 'EOF'
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
READ_TIMEOUT=30s
WRITE_TIMEOUT=30s
IDLE_TIMEOUT=120s

# Database Configuration (use managed service credentials)
DB_HOST=your-postgres-host.amazonaws.com
DB_PORT=5432
DB_USER=oauth_service
DB_PASSWORD=your-secure-password
DB_NAME=oauth_production
DB_SSL_MODE=require

# Security Configuration
JWT_SECRET=your-256-bit-secret-key-here-must-be-secure
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=168h
AUTH_CODE_TTL=10m

# Production Security Settings
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=1m
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Monitoring
METRICS_ENABLED=true
LOG_LEVEL=info
EOF
```

### 2. Generate Secure Secrets

```bash
# Generate JWT secret (256-bit)
JWT_SECRET=$(openssl rand -base64 32)
echo "JWT_SECRET=$JWT_SECRET"

# Generate database password
DB_PASSWORD=$(openssl rand -base64 24)
echo "DB_PASSWORD=$DB_PASSWORD"

# Generate TLS certificates for testing
openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -days 365 -nodes \
  -subj "/CN=oauth.yourdomain.com"
```

## Database Setup

### 1. PostgreSQL Production Setup

```sql
-- Create production database and user
CREATE DATABASE oauth_production;
CREATE USER oauth_service WITH ENCRYPTED PASSWORD 'your-secure-password';

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE oauth_production TO oauth_service;
GRANT ALL ON SCHEMA public TO oauth_service;
GRANT ALL ON ALL TABLES IN SCHEMA public TO oauth_service;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO oauth_service;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO oauth_service;

-- Enable required extensions
\c oauth_production;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set up database monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

### 2. Database Migration Script

```bash
#!/bin/bash
# Database migration script

set -e

DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_NAME=${DB_NAME:-oauth_production}
DB_USER=${DB_USER:-oauth_service}

echo "Running database migrations..."

# Check database connectivity
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "SELECT 1;" > /dev/null

# Run schema creation
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME << 'EOF'
-- Create tables if they don't exist
CREATE TABLE IF NOT EXISTS schema_versions (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT NOW()
);

-- Check current schema version
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_versions WHERE version = 1) THEN
        -- Run initial schema creation
        -- (Your existing CREATE TABLE statements here)
        INSERT INTO schema_versions (version) VALUES (1);
    END IF;
END $$;
EOF

echo "Database migration completed successfully!"
```

## Security Configuration

### 1. TLS/SSL Setup

```yaml
# tls-config.yaml
apiVersion: v1
kind: Secret
metadata:
  name: oauth-server-tls
  namespace: oauth-server
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTi... # base64 encoded certificate
  tls.key: LS0tLS1CRUdJTi... # base64 encoded private key
```

### 2. Security Headers Configuration

```yaml
# security-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-headers
  namespace: oauth-server
data:
  nginx.conf: |
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'" always;
```

## Docker Deployment

### 1. Production Dockerfile

```dockerfile
# Dockerfile.production
FROM golang:1.24-alpine AS builder

# Install security updates
RUN apk add --no-cache ca-certificates git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags="-w -s" -o oauth-server ./cmd/server

# Final stage - minimal image
FROM scratch

# Import CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /app/oauth-server /oauth-server

# Non-root user
USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/oauth-server"]
```

### 2. Docker Compose for Local Testing

```yaml
# docker-compose.production.yml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: oauth_production
      POSTGRES_USER: oauth_service
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/setup.sql:/docker-entrypoint-initdb.d/setup.sql
    ports:
      - "5432:5432"
    restart: unless-stopped

  oauth-server:
    build:
      context: .
      dockerfile: Dockerfile.production
    environment:
      DB_HOST: postgres
      DB_PASSWORD: ${DB_PASSWORD}
      JWT_SECRET: ${JWT_SECRET}
    ports:
      - "8080:8080"
    depends_on:
      - postgres
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  postgres_data:
  grafana_data:
```

## Kubernetes Deployment

### 1. Production-Ready Deployment

```bash
# Deploy to production namespace
kubectl create namespace oauth-production

# Apply security policies first
kubectl apply -f deployments/kubernetes/network-policy.yaml -n oauth-production

# Deploy database
kubectl apply -f deployments/kubernetes/postgres.yaml -n oauth-production

# Wait for database to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n oauth-production --timeout=300s

# Deploy secrets and config
kubectl apply -f deployments/kubernetes/secret.yaml -n oauth-production
kubectl apply -f deployments/kubernetes/configmap.yaml -n oauth-production

# Deploy OAuth server
kubectl apply -f deployments/kubernetes/deployment.yaml -n oauth-production
kubectl apply -f deployments/kubernetes/service.yaml -n oauth-production
kubectl apply -f deployments/kubernetes/hpa.yaml -n oauth-production

# Deploy ingress with TLS
kubectl apply -f deployments/kubernetes/ingress.yaml -n oauth-production
```

### 2. Production Ingress Configuration

```yaml
# ingress-production.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth-server-ingress
  namespace: oauth-production
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "1000"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header X-Frame-Options "DENY" always;
      add_header X-Content-Type-Options "nosniff" always;
      add_header X-XSS-Protection "1; mode=block" always;
spec:
  tls:
  - hosts:
    - oauth.yourdomain.com
    secretName: oauth-server-tls
  rules:
  - host: oauth.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: oauth-server-service
            port:
              number: 80
```

## Monitoring and Observability

### 1. Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'oauth-server'
    static_configs:
      - targets: ['oauth-server-service:80']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

rule_files:
  - "oauth_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### 2. Grafana Dashboard

```json
{
  "dashboard": {
    "title": "OAuth 2.0 Server Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(oauth_requests_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Token Operations",
        "type": "graph",
        "targets": [
          {
            "expr": "oauth_tokens_issued_total",
            "legendFormat": "Tokens Issued"
          },
          {
            "expr": "oauth_tokens_revoked_total",
            "legendFormat": "Tokens Revoked"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(oauth_errors_total[5m])",
            "legendFormat": "Errors/sec"
          }
        ]
      }
    ]
  }
}
```

### 3. Alert Rules

```yaml
# oauth_rules.yml
groups:
  - name: oauth-server
    rules:
      - alert: OAuthServerDown
        expr: up{job="oauth-server"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "OAuth server is down"

      - alert: HighErrorRate
        expr: rate(oauth_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"

      - alert: DatabaseConnectionFailed
        expr: oauth_database_connections_failed_total > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database connection failures"
```

## Load Balancing and Scaling

### 1. Horizontal Pod Autoscaler

```yaml
# hpa-production.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: oauth-server-hpa
  namespace: oauth-production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: oauth-server
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 60
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 70
```

### 2. Pod Disruption Budget

```yaml
# pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: oauth-server-pdb
  namespace: oauth-production
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: oauth-server
```

## Performance Optimization

### 1. Database Optimization

```sql
-- Create indexes for performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_tokens_client_id 
ON access_tokens(client_id) WHERE NOT revoked;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_tokens_expires_at 
ON access_tokens(expires_at) WHERE NOT revoked;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_token 
ON refresh_tokens(token) WHERE NOT revoked;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_authorization_codes_code 
ON authorization_codes(code) WHERE NOT used;

-- Configure PostgreSQL for performance
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
SELECT pg_reload_conf();
```

### 2. Application Performance Tuning

```yaml
# performance-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: performance-config
data:
  GOMAXPROCS: "2"
  GOGC: "100"
  GOMEMLIMIT: "200MiB"
```

## Backup and Recovery

### 1. Database Backup Script

```bash
#!/bin/bash
# backup-database.sh

set -e

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="oauth_backup_$DATE.sql"

# Create backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > "$BACKUP_DIR/$BACKUP_FILE"

# Compress backup
gzip "$BACKUP_DIR/$BACKUP_FILE"

# Upload to cloud storage (example with AWS S3)
aws s3 cp "$BACKUP_DIR/$BACKUP_FILE.gz" s3://your-backup-bucket/oauth-server/

# Clean up old backups (keep last 30 days)
find $BACKUP_DIR -name "oauth_backup_*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE.gz"
```

### 2. Automated Backup with CronJob

```yaml
# backup-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: oauth-db-backup
  namespace: oauth-production
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15-alpine
            command: ["/bin/sh"]
            args:
            - -c
            - |
              pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME | gzip > /backup/oauth_$(date +%Y%m%d_%H%M%S).sql.gz
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: oauth-server-secrets
                  key: DB_PASSWORD
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

## Security Hardening

### 1. Network Security

```yaml
# network-security.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: oauth-server-strict
  namespace: oauth-production
spec:
  podSelector:
    matchLabels:
      app: oauth-server
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: nginx-ingress
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

### 2. Pod Security Standards

```yaml
# pod-security.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: oauth-production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

## Troubleshooting

### Common Issues and Solutions

1. **Database Connection Issues**
   ```bash
   # Test database connectivity
   kubectl exec -it oauth-server-xxx -- /bin/sh
   # Inside pod: test connection
   nc -zv postgres-service 5432
   ```

2. **Certificate Issues**
   ```bash
   # Check certificate status
   kubectl describe certificate oauth-server-tls -n oauth-production
   
   # Renew certificate
   kubectl delete secret oauth-server-tls -n oauth-production
   ```

3. **Performance Issues**
   ```bash
   # Check resource usage
   kubectl top pods -n oauth-production
   
   # Check logs for errors
   kubectl logs -f deployment/oauth-server -n oauth-production
   ```

4. **Token Validation Failures**
   ```bash
   # Check JWT secret consistency
   kubectl get secret oauth-server-secrets -o yaml -n oauth-production
   ```

This deployment guide provides a comprehensive foundation for running the OAuth 2.0 server in production with enterprise-grade security, monitoring, and reliability.