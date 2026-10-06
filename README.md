# Unified Ransomware Detection & Recovery System

URDS is a college capstone microservices project covering Phases 1-4 (Weeks 1-16): detection, classification, tamper-evident audit, response, recovery, and the integration layer that ties them together.

## Service status

All six services are implemented. Nothing in `services/` is a stub any more.

| Service | Port | Owner | State |
|---|---|---|---|
| Monitor | 8001 | AS | Real. Watchdog file events, Shannon entropy, magic-byte false-positive mitigation, SHA-256 hashing, and fan-out to ML → Ledger → Response. Picks a polling watcher on mounts that carry no inotify — a Windows bind mount is `9p`, where native watches are accepted and never fire. |
| ML Engine | 8002 | NI | Real. Serves two trained XGBoost models: the EMBER static-PE classifier (`ember_vector`) and a behavioural classifier over the Monitor's feature dict. Metrics are read from disk, not hardcoded. |
| Ledger | 8003 | SI | Real. SQLite hash chain with tamper detection; full-chain verification of 1,000 blocks measured at 3.1ms median (2.1–5.7ms over 50 warm runs) against a <50ms target. |
| Response | 8004 | AS + SI | Real. AS owns terminate/isolate/trigger (psutil process termination, platform-aware network isolation); SI owns `recovery/` (VSS snapshots, restore, integrity verification). |
| Gateway | 8000 | SH | Real. JWT auth, per-tier rate limiting, service proxies, and the `/analyze` orchestration. |
| Dashboard | 8501 | SH | Real. Streamlit, 1s auto-refresh, live event feed and ledger evidence. Streamlit pin raised to 1.51.0 so one environment can hold Pillow 12 — re-verification pending (`FIXES.md`, defect 7). |

Two things are deliberately *not* real, and both say so at runtime rather than faking a result:

- **VSS snapshots** need Windows *and an elevated process*. Verified on Windows 11 build 26200: a real shadow copy of `C:\` in 2.8s against the 30s target. On Linux/macOS `VSSManager` reports `supported: false` with the reason, and recovery falls back to a directory-backed snapshot root so the path stays exercisable.
- **Network isolation** builds real `iptables`/`pfctl`/`netsh` rules but only applies them when `RESPONSE_ISOLATION_ENABLED=true`. Otherwise it returns `enforced: false` along with the rules it would have applied.

**Killing a process needs Administrator rights and Windows file auditing.** The Monitor can only name the process that wrote a file from the Windows Security log (event 4663), which it can read only when it runs elevated, and only for folders that have an audit rule. Set that up once per watched folder with `powershell -ExecutionPolicy Bypass -File scripts/setup_attribution_audit.ps1 -WatchPath <dir>` (Administrator; `-Verify` checks it, `-Revert` undoes it), then start the Monitor from an elevated shell and check `GET /monitor/attribution`. Without that, the Monitor still detects encryption and still records and responds, but attribution is `unknown` and, by design, it never kills a process it cannot identify. See `docs/PROCESS_ATTRIBUTION.md`.

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

**Suspend-first response and Docker.** `POST /response/suspend` freezes a
process under a lease that ends on its own. It is resumed when the lease
expires, when Response stops, or by a watchdog process if Response is killed
outright. In Docker Compose the Response container has its own PID
namespace: the host PID the Monitor names does not exist inside it, or names
a different process. So Response **refuses every suspend there** with
`409 PID_NAMESPACE_ISOLATED`, and records the refusal in the ledger as a
`process_suspended` block with `outcome: refused`. It does not try. To
suspend host processes, run Response natively on the host, as on the
Windows VM. A container started with `pid: host` can declare it with
`RESPONSE_PID_NAMESPACE=host`. When the Monitor runs as a separate process,
set `URDS_MONITOR_PID` to its PID so Response refuses to suspend the Monitor
or its ancestors.

The Monitor side (freeze-first: suspend a sole writer as soon as a kernel-grade answer names it, then kill it at the horizon if the kill gate is satisfied then, or resume it) is built, on by default and switchable with `MONITOR_SUSPEND_FIRST=0` (FIXES.md, defect 26, "The Monitor side"; `docs/PROCESS_ATTRIBUTION.md`). It is **not proven on the VM**, and it only helps against an attacker still running when the first audit record arrives; an operator can also still suspend through the gateway.

Two switches govern how the Monitor's blocks reach the ledger on a slow disk: `LEDGER_MAX_BATCH` (default 64; 1 commits each block alone) and `MONITOR_DEFER_TAIL_BLOCKS` (default on; 0 writes the last block of each incident inline). Neither changes what is in the chain or the order inside one incident (FIXES.md, defect 28).

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

The simulator sweep is the held-out evidence for detection — thirteen ransomware
families run past a live watcher, each one measured on what caught it and on
whether `--restore` returned every file byte for byte:

```bash
URDS_WRITE_REPORTS=1 python scripts/simulator_sweep.py --files 8 --settle 2.0
```

## Documentation

| Document | What it covers |
|---|---|
| [`docs/APPROACH.md`](docs/APPROACH.md) | Design decisions, and §8 where the implementation departs from the specification |
| [`docs/DETECTION_HARDENING.md`](docs/DETECTION_HARDENING.md) | Five defects found by reading the source, the fixes, and the before/after evidence |
| [`docs/test_cases.md`](docs/test_cases.md) | How each test case in the reference document maps to a test here |
| [`docs/openapi/gateway.yaml`](docs/openapi/gateway.yaml) | The authoritative API contract (`docs/api_spec.md` is superseded) |

## Future Work

Out of scope for Weeks 1-16:

- CI/CD pipeline
- Production load balancing
- Real blockchain anchoring
- Production authentication and secret management
- 95%+ coverage target
