# SI Track — Ledger & Recovery

Blockchain & Recovery Architect slice of the Unified Ransomware Detection &
Recovery System. Phases 1–4 (weeks 1–16, semester 1).

Two things live here:

1. **Ledger service** (port 8003) — tamper-proof hash-chain audit log
2. **Recovery module** — `POST /response/recover` inside the Response service
   (port 8004), plus VSS snapshots and integrity verification

Terminate/isolate on the Response service belong to AS and are untouched.

---

## Quick start

```bash
docker-compose up -d ledger response
```

Standalone, without Docker:

```bash
pip install -r services/ledger/requirements.txt
LEDGER_DB_PATH=./data/ledger/ledger.db uvicorn main:app --port 8003 --app-dir services/ledger
```

```bash
pip install -r services/response/requirements.txt
LEDGER_URL=http://localhost:8003 uvicorn app:app --port 8004 --app-dir services/response
```

On Windows PowerShell, set the variables first (`$env:LEDGER_DB_PATH = "..."`)
and then run uvicorn from inside the service directory.

## Tests

```bash
cd services/ledger && python -m pytest tests -q
```

```bash
cd services/response && python -m pytest recovery/tests -q
```

93 tests, no network or Windows dependency — they pass on Linux and macOS too.

## Demo (TC-04 + TC-05)

With both services running:

```bash
python scripts/si_demo.py --db data/ledger/ledger.db
```

Writes a before/after transcript to `reports/si_demo_evidence.txt`: file hash and
entropy before the attack, after encryption, and after recovery, then the chain
verification and the tamper detection. Latest run is committed there.

---

## Endpoints

### Ledger (8003)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/ledger/log` | Append an event to the chain |
| `GET` | `/ledger/verify` | Full-chain integrity check (target <50ms) |
| `GET` | `/ledger/blocks` | Paginated read — `offset`, `limit`, `event_type`, `file_path`, `newest_first` |
| `GET` | `/ledger/entries` | Newest-first view the dashboard already uses |
| `GET` | `/health` | Liveness + block count |

```jsonc
// POST /ledger/log
{"event_type": "file_encrypted",
 "event_data": {"file_path": "C:\\data\\a.doc", "process_id": 1234, "entropy": 7.89}}

// -> 200
{"block_id": 42, "current_hash": "...", "previous_hash": "...",
 "timestamp": "2026-08-06T06:43:20.111099Z", "tamper_proof": true}
```

```jsonc
// GET /ledger/verify
{"valid": true, "blocks_checked": 1000, "invalid_block_id": null, "verification_time_ms": 3.659}
```

### Recovery (8004)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/response/recover` | Restore files from a snapshot |
| `GET` | `/response/recover/status` | Whether VSS works on this host, and why not if it doesn't |

```jsonc
// POST /response/recover
{"snapshot_id": "snap_demo", "files": ["C:\\data\\a.doc"], "verify_integrity": true}

// -> 200
{"status": "success", "files_recovered": 1, "integrity_verified": true,
 "timestamp": "...", "files": [{"file_path": "...", "restored": true,
 "integrity_verified": true, "restored_hash": "...", "expected_hash": "...", "reason": null}]}
```

`status` is `success`, `partial`, or `failed`. `files` is an extra field beyond
the spec'd contract — the four contract fields are always present.

Errors on both services use the project envelope:
`{"error": {"code", "message", "timestamp", "request_id"}, "details": {}}`.

---

## How the two halves connect

The integrity check is the join between them: after restoring a file, recovery
hashes it and compares against **the last hash the ledger already holds for that
path**. So `integrity_verified: true` means the restored bytes match what the
system recorded before the incident — not merely that a copy operation
succeeded.

If no ledger event ever carried a hash for that path, the file is still restored
but reported `integrity_verified: false` with a reason. Claiming a verification
we did not perform would be worse than admitting we could not.

**Ask for AS/NI:** include `file_hash` in `event_data` whenever you log an event
about a file you have just hashed. That is what makes the check possible.
`sha256` and `hash` are accepted as aliases.

---

## Platform reality: VSS

Volume Shadow Copy is Windows-only, and **the Response service's container is
Linux**. Snapshot creation therefore cannot work inside `docker-compose`.

What happens instead:

- On startup the 6-hour snapshot scheduler checks the platform. If VSS is
  unavailable it logs the reason and **does not start** — the service comes up
  normally. Verified: `Snapshot scheduler not started: pywin32 is not installed.`
- `GET /response/recover/status` reports exactly why.
- Snapshot calls raise `VSSUnavailableError`, surfaced as HTTP 503 with a
  readable message rather than a 500.

To exercise recovery anywhere (container, CI, Linux), set
`RECOVERY_SNAPSHOT_ROOT`. Then `<root>/<snapshot_id>/<path-without-drive>` is
treated as a snapshot. Compose sets this to `/app/snapshots`. **It is a dev and
test affordance, not a backup mechanism** — real protection needs the Response
service running natively on Windows with `pywin32` installed.

### Why WMI and not `vssadmin`

`vssadmin` has no `Create Shadow` verb on client editions of Windows — only
Server SKUs. On the target machine (Windows 11 Home, build 26100) `vssadmin /?`
lists only Delete/List/Resize operations, while `Win32_ShadowCopy` exposes
`Create`. Since the team develops and demos on client Windows, shelling out to
`vssadmin` would fail everywhere except a server, so creation goes through WMI.
`vssadmin list shadows` *is* available on client editions and is kept as the
enumeration fallback.

Snapshot creation also requires an elevated process; the manager checks and says
so rather than failing obscurely.

---

## Design decisions

**Canonical JSON.** `event_data` is hashed as the exact text stored in the row
(`sort_keys=True`, no whitespace). Verification re-hashes the stored string, not
a re-serialised object — otherwise key ordering could look identical to
tampering. Full rationale in [`services/ledger/README.md`](services/ledger/README.md).

**`event_type` is inside the hash preimage,** so a `file_encrypted` block cannot
be relabelled `benign_write` while keeping a valid hash.

**Append-only.** No update or delete path exists in the service. Tampering means
writing to the SQLite file directly — which is exactly what TC-05 does, and what
verification catches.

**Metadata only.** Paths, hashes, entropy, PIDs. Never file contents (§1.5).

**Two containers, one chain.** Recovery reaches the ledger over HTTP rather than
opening the SQLite file, because two writers would race and fork the chain.

---

## Measured against the targets

| Target (Table 5.9) | Result |
|---|---|
| Ledger verification <50ms | **3.7ms** at 1,000 blocks; 0.5ms at 100; 23–46ms at 5,000 |
| File recovery success | TC-04 passes; 100% across the test suite |
| Successful tampering attempts | 0 — every mutation tested is detected |
| Snapshot creation <30s | Code path built and unit-tested; **not measured on real hardware** (see below) |

Verification is a single query plus an in-memory walk. It stays under 50ms to
roughly 5,000 blocks, then approaches the limit — worth revisiting in Phase 5 if
the chain is expected to grow past that (incremental verification from the last
known-good block would be the fix).

### Not verified on real hardware

Real VSS snapshot creation could not be executed in the development environment:
it needs an elevated shell and `pywin32`, and this machine has neither. The code
path, error mapping and scheduling are unit-tested against mocks, but the
"snapshot created in under 30s" number has not been observed.

To close that, from an **Administrator** PowerShell with the ledger running:

```bash
python scripts/verify_vss.py --volume C:\
```

It reports platform support, creation time against the 30s target, whether the
snapshot is listed, and whether a `snapshot_created` block reached the ledger.

---

## For teammates

**SH (gateway).** `services/gateway/routers/ledger.py` proxies `/ledger/log` and
`/ledger/entries`. Both still work — `/ledger/entries` was kept for exactly this
reason. `/ledger/verify` and `/ledger/blocks` have no gateway route yet, so the
dashboard can't reach them through 8000. Two additions in that router:

```python
@router.get("/verify")
async def verify_chain(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", LEDGER_URL, "/ledger/verify")


@router.get("/blocks")
async def ledger_blocks(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", LEDGER_URL, "/ledger/blocks")
```

Also note hashes are now **64 characters** (full SHA-256) where the stub
truncated to 32. The dashboard renders them through `short_hash()` so it is
display-safe, but any test asserting `len(hash) == 32` needs updating.

**AS (response service).** `services/response/app.py` still has your
terminate/isolate/trigger placeholders. My changes to that file are three small
marked blocks: the `recovery` import, `app.include_router(recovery_router)`, and
a `lifespan` that starts the snapshot scheduler. The stub `/response/recover` was
removed since `recovery/` now serves it. When you replace the file, keep those
three and everything under `services/response/recovery/` works unchanged.
`Dockerfile` also gained `COPY recovery ./recovery`.

**Monitor/ML.** Nothing required. Only the `file_hash` request above.

---

## Layout

```
services/ledger/
  main.py            FastAPI app and endpoints
  app.py             shim re-exporting main:app
  hash_chain.py      HashChainLedger — append, verify, paginate
  database.py        SQLite connection, schema, canonical JSON
  models.py          Pydantic models
  README.md          schema + rationale (Phase 1 deliverable)
  tests/             39 tests
services/response/recovery/
  recovery.py        RecoveryManager + /response/recover router
  vss_manager.py     VSSManager — snapshots, scheduling, platform detection
  ledger_client.py   HTTP client for the ledger
  tests/             54 tests, including TC-04/TC-05 integration
scripts/
  si_demo.py         TC-04 + TC-05 demo, writes reports/si_demo_evidence.txt
  verify_vss.py      Phase 3 hardware check (needs elevation + pywin32)
```

## Phase 5 handoff (weeks 17+, out of scope here)

- `blockchain_anchor` exists on `LedgerBlock`, always `null`. It is deliberately
  **not** a SQLite column yet — adding it means first deciding whether the anchor
  sits inside or outside the hash preimage, which shouldn't be settled before the
  anchoring design exists.
- Anchoring granularity: hashing every block to Polygon is not affordable.
  Periodic Merkle-root anchoring is the usual approach.
- Verification cost grows linearly; incremental verification from a checkpoint
  becomes worthwhile past ~5,000 blocks.
- TC-12 (blockchain anchoring) and the security audit are Phase 5–6.
