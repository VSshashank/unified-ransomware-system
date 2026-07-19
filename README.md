# Unified Ransomware Detection & Recovery System

URDS is a college capstone microservices project. This branch contains SH's integration and DevOps scope for Weeks 1-16: API Gateway, Dashboard v1, Docker Compose orchestration, OpenAPI contract, and lightweight placeholder backend services for end-to-end testing.

The Monitor, ML Engine, Ledger, and Response service internals are teammate-owned. The implementations in this repo are clearly marked stubs so the gateway and dashboard can be tested before those real services are merged.

## Quick Start

```bash
cp .env.example .env
docker-compose up -d --build
```

Open:

- Gateway health: http://localhost:8000/health
- Dashboard: http://localhost:8501

Useful commands:

```bash
docker-compose ps
docker-compose logs -f gateway
docker-compose logs -f dashboard
docker-compose down
docker-compose up -d --build
```

## Local Gateway Testing

```bash
cd services/gateway
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

The gateway exposes a development-only token endpoint:

```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"sub":"user_id_123","role":"admin","tier":"enterprise"}'
```

Use the returned token as:

```bash
Authorization: Bearer <token>
```

This endpoint is only a Phase 4 placeholder and must be replaced with real identity management later.

## API Contract

The gateway OpenAPI contract lives at `docs/openapi/gateway.yaml`. It covers:

- Monitor routes: `/monitor/start`, `/monitor/stop`, `/monitor/status`, `/monitor/events`
- ML routes: `/predict`, `/model/metrics`
- Ledger routes: `/ledger/log`, `/ledger/entries`
- Response routes: `/response/terminate`, `/response/isolate`, `/response/recover`, `/response/trigger`
- Composite route: `/analyze`
- Health and development auth endpoints

Every gateway error uses:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "timestamp": "2026-01-31T10:05:00Z",
    "request_id": "req_abc123"
  },
  "details": {}
}
```

## Branching and Commits

Use these branch conventions:

- `feature/SH-api-gateway`
- `feature/SH-dashboard`
- `bugfix/issue-###`

Use conventional commits:

- `feat(gateway): add analyze orchestration`
- `fix(dashboard): handle empty event feed`
- `test(gateway): cover JWT rejection`

## Swapping Stubs for Real Services

The current backend services are placeholders:

- `services/monitor`
- `services/ml-engine`
- `services/ledger`
- `services/response`

To swap in teammate implementations, keep the same container ports and endpoint contracts, or update the gateway environment variables in `.env`/`docker-compose.yml`:

- `MONITOR_URL`
- `ML_URL`
- `LEDGER_URL`
- `RESPONSE_URL`

The gateway should not need internal service logic changes as long as the contracts remain stable.

## Future Work

Out of scope for Weeks 1-16:

- CI/CD pipeline
- Production load balancing
- Real blockchain anchoring
- Production authentication and secret management
- 95%+ coverage target
