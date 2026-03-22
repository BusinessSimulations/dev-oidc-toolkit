# Health Checks

Dev OIDC Toolkit exposes health check endpoints that can be used by container orchestrators (such as Docker, Kubernetes,
or Docker Compose) to determine when the service is live and ready to accept traffic.

## Endpoints

| Endpoint | Description |
|---|---|
| `GET /healthz/live` | Liveness probe — returns `200 Healthy` when the application process is running. |
| `GET /healthz/ready` | Readiness probe — returns `200 Healthy` when the application is ready to serve requests, including verifying database connectivity when SQLite is configured. |

Both endpoints return a plain-text body of `Healthy` and an HTTP `200` status code when healthy, or `503 Unhealthy`
when a check fails.

### Readiness and database checks

When the application is configured to use a SQLite database (via `Database.SqliteFile`), the `/healthz/ready` endpoint
also verifies that the database is reachable. The `/healthz/live` endpoint never checks the database — it only
reports whether the process itself is running.

When using the default in-memory database, both endpoints behave identically.

## Docker HEALTHCHECK

The official Docker image already includes a `HEALTHCHECK` instruction that uses `curl` to poll `/healthz/live` every
30 seconds:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/healthz/live || exit 1
```

No extra configuration is required to enable this — it works out of the box.

## Docker Compose example

You can use the readiness endpoint to make dependent services wait until Dev OIDC Toolkit is healthy before starting:

```yaml
services:
  dev-oidc-toolkit:
    image: ghcr.io/businesssimulations/dev-oidc-toolkit
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/healthz/ready"]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 5s

  my-app:
    image: my-app
    depends_on:
      dev-oidc-toolkit:
        condition: service_healthy
```
