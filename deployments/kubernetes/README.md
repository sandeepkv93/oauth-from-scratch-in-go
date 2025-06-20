# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the OAuth 2.0 server to a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (v1.20+)
- kubectl configured
- NGINX Ingress Controller
- cert-manager (optional, for TLS)
- Metrics server (for HPA)

## Quick Start

1. **Create the namespace and deploy PostgreSQL**:
   ```bash
   kubectl apply -f namespace.yaml
   kubectl apply -f secret.yaml
   kubectl apply -f configmap.yaml
   kubectl apply -f postgres.yaml
   ```

2. **Wait for PostgreSQL to be ready**:
   ```bash
   kubectl wait --for=condition=ready pod -l app=postgres -n oauth-server --timeout=300s
   ```

3. **Deploy the OAuth server**:
   ```bash
   kubectl apply -f deployment.yaml
   kubectl apply -f service.yaml
   kubectl apply -f hpa.yaml
   kubectl apply -f network-policy.yaml
   ```

4. **Deploy Ingress (optional)**:
   ```bash
   # Update the host in ingress.yaml first
   kubectl apply -f ingress.yaml
   ```

## Using Kustomize

You can also deploy using Kustomize:

```bash
kubectl apply -k .
```

## Configuration

### Secrets

Before deploying, update the secrets in `secret.yaml`:

```bash
# Generate base64 encoded values
echo -n "your-jwt-secret" | base64
echo -n "your-db-password" | base64
```

### ConfigMap

Update the configuration in `configmap.yaml` as needed for your environment.

### Ingress

Update the host in `ingress.yaml` to match your domain:

```yaml
- host: oauth.yourdomain.com
```

## Monitoring

The deployment includes:

- **Health checks**: Liveness and readiness probes
- **Metrics**: Prometheus annotations for scraping
- **HPA**: Horizontal Pod Autoscaler for scaling
- **Resource limits**: CPU and memory constraints

## Security

Security features included:

- **Network policies**: Restrict network traffic
- **Security context**: Non-root user, read-only filesystem
- **TLS**: HTTPS termination at ingress
- **Secrets**: Sensitive data stored in Kubernetes secrets

## Scaling

The deployment includes Horizontal Pod Autoscaler (HPA) that scales based on:

- CPU utilization (target: 70%)
- Memory utilization (target: 80%)
- Min replicas: 2
- Max replicas: 10

## Database

PostgreSQL is deployed with:

- **Persistent storage**: 10Gi PVC
- **Resource limits**: 512Mi memory, 500m CPU
- **Health checks**: pg_isready probes
- **Security**: Non-root user, network policies

## Troubleshooting

### Check pod status:
```bash
kubectl get pods -n oauth-server
```

### View logs:
```bash
kubectl logs -f deployment/oauth-server -n oauth-server
```

### Check service endpoints:
```bash
kubectl get endpoints -n oauth-server
```

### Test connectivity:
```bash
kubectl port-forward service/oauth-server-service 8080:80 -n oauth-server
```

### Check HPA status:
```bash
kubectl get hpa -n oauth-server
```

## Production Considerations

1. **TLS Certificates**: Use cert-manager or provide your own certificates
2. **Database**: Consider using a managed database service
3. **Secrets Management**: Use external secret management (e.g., Vault, AWS Secrets Manager)
4. **Monitoring**: Deploy Prometheus and Grafana for comprehensive monitoring
5. **Backup**: Implement database backup strategy
6. **Multi-region**: Deploy across multiple availability zones
7. **CI/CD**: Integrate with your deployment pipeline

## Cleanup

To remove the deployment:

```bash
kubectl delete -k .
# Or
kubectl delete namespace oauth-server
```