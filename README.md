# Unified Ransomware Detection & Recovery System

URDS is a college capstone microservices project covering Phases 1-4 (Weeks 1-16): detection, classification, tamper-evident audit, response, recovery, and the integration layer that ties them together.

## Service status

All six services are implemented. Nothing in `services/` is a stub any more.

| Service | Port | Owner | State |
|---|---|---|---|
| Monitor | 8001 | AS | Real. Watchdog file events, Shannon entropy, magic-byte false-positive mitigation, SHA-256 hashing, and fan-out to ML → Ledger → Response. Picks a polling watcher on mounts that carry no inotify — a Windows bind mount is `9p`, where native watches are accepted and never fire. |
| ML Engine | 8002 | NI | Real. Serves two trained XGBoost models: the EMBER static-PE classifier (`ember_vector`) and a behavioural classifier over the Monitor's feature dict. Metrics are read from disk, not hardcoded. |
| Ledger | 8003 | SI | Real. SQLite hash chain with tamper detection; full-chain verification measured at ~3.7ms against a <50ms target. |
| Response | 8004 | AS + SI | Real. AS owns terminate/isolate/trigger (psutil process termination, platform-aware network isolation); SI owns `recovery/` (VSS snapshots, restore, integrity verification). |
| Gateway | 8000 | SH | Real. JWT auth, per-tier rate limiting, service proxies, and the `/analyze` orchestration. |
| Dashboard | 8501 | SH | Real. Streamlit, 1s auto-refresh, live event feed and ledger evidence. |

Two things are deliberately *not* real, and both say so at runtime rather than faking a result:

- **VSS snapshots** need Windows *and an elevated process*. Verified on Windows 11 build 26200: a real shadow copy of `C:\` in 2.8s against the 30s target. On Linux/macOS `VSSManager` reports `supported: false` with the reason, and recovery falls back to a directory-backed snapshot root so the path stays exercisable.
- **Network isolation** builds real `iptables`/`pfctl`/`netsh` rules but only applies them when `RESPONSE_ISOLATION_ENABLED=true`. Otherwise it returns `enforced: false` along with the rules it would have applied.

Trained model artifacts (`models/`) and datasets (`data/`) are gitignored. Rebuild them with `python src/train_behavioral_model.py` and, once a dataset is fetched via `src/fetch_ember_subset.py`, `python src/train_ember_model.py`.

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

The gateway exposes a development-only token endpoint. An empty POST returns a
`free` token, which can read but cannot act:

```bash
curl -X POST http://localhost:8000/auth/token
```

Anything above `free` needs the shared bootstrap secret
(`DEV_TOKEN_BOOTSTRAP_SECRET`, defaulted in `docker-compose.yml`):

```bash
curl -X POST http://localhost:8000/auth/token -H "Content-Type: application/json" -H "X-Bootstrap-Secret: dev-bootstrap-change-me" -d '{"sub":"user_id_123","role":"admin","tier":"enterprise"}'
```

Use the returned token as:

```bash
Authorization: Bearer <token>
```

This endpoint is only a Phase 4 placeholder — it verifies no identity — and must
be replaced with real identity management later. Set `ALLOW_DEV_TOKENS=false` to
remove it entirely.

### Roles

Authentication (401) and authorization (403) are separate. Roles, least
privileged first: `free`, `premium`, `enterprise`, `admin`.

| Routes | Required role |
|---|---|
| All `GET` routes | any authenticated role |
| `POST /monitor/start`, `/analyze`, `/predict`, `/ledger/log` | `admin` or `enterprise` |
| `POST /monitor/stop`, all `/response/*` | `admin` |

### Ports

Only the gateway (`8000`) and dashboard (`8501`) are published on all
interfaces. Monitor, ML engine, ledger, and response bind to `127.0.0.1` — they
carry no authentication of their own, so they are reachable from the host but
not from the network.

## API Contract

The gateway OpenAPI contract lives at `docs/openapi/gateway.yaml`. It covers:

- Monitor routes: `/monitor/start`, `/monitor/stop`, `/monitor/status`, `/monitor/events`
- ML routes: `/predict`, `/model/metrics`
- Ledger routes: `/ledger/log`, `/ledger/entries`, `/ledger/verify`, `/ledger/blocks`
- Response routes: `/response/terminate`, `/response/isolate`, `/response/recover`, `/response/trigger`
- Composite route: `/analyze`
- Health and development auth endpoints

`tests/test_gateway.py` asserts the contract and the implementation match in both directions, so a route added to one without the other fails the suite.

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

## Service Wiring

Services find each other by URL, so any one of them can be run outside Compose (natively, or against a remote host) by pointing the others at it:

- `MONITOR_URL`
- `ML_URL`
- `LEDGER_URL`
- `RESPONSE_URL`

This is how the Response service gets run on Windows for real VSS snapshots while the rest of the stack stays in Compose.

The gateway needs no internal service logic changes as long as the contracts in `docs/openapi/gateway.yaml` hold.

## Running the Tests

```bash
for svc in gateway ledger monitor ml-engine response; do (cd services/$svc && python -m pytest -q); done
```

Benchmarks that assert the spec's numeric targets are marked `benchmark`; run them with output shown to see the measured values:

```bash
cd services/monitor && python -m pytest -m benchmark -q -s
```

Benchmarks always measure and always assert, but they only write their numbers
back to `reports/` when asked. Those files are committed evidence, so a plain
test run leaves them alone rather than producing diffs anyone could commit by
accident. To refresh them deliberately:

```bash
URDS_WRITE_REPORTS=1 python -m pytest -m benchmark -q -s
```

## Future Work

Out of scope for Weeks 1-16:

- CI/CD pipeline
- Production load balancing
- Real blockchain anchoring
- Production authentication and secret management
- 95%+ coverage target
