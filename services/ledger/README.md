# Ledger Service (port 8003)

Tamper-proof audit log for URDS. Every meaningful event in the system — a file
change, an ML verdict, a process kill, a recovery — gets appended here as a
block whose hash commits to the hash of the block before it. Editing history
after the fact breaks the chain, and `GET /ledger/verify` says exactly where.

Owner: SI (Blockchain & Recovery Architect). Phases 1–4.

---

## Schema

### `LedgerBlock` (Pydantic, `models.py`)

| Field | Type | Notes |
|---|---|---|
| `block_id` | `int` | Maps to the SQLite `id` column |
| `timestamp` | `datetime` | UTC, ISO-8601 |
| `event_type` | `str` | e.g. `file_encrypted`, `analysis`, `snapshot_created` |
| `event_data` | `dict` | Free-form metadata; see contract below |
| `previous_hash` | `str` | 64 hex chars; `"0" * 64` for the first block |
| `current_hash` | `str` | 64 hex chars, SHA-256 |
| `blockchain_anchor` | `str \| None` | **Always null in Phases 1–4.** Phase 5 Polygon anchoring |

### SQLite `blocks` table (`database.py`)

```sql
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    event_type TEXT,
    event_data TEXT,      -- canonical JSON, see below
    previous_hash TEXT,
    current_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_event_type ON blocks(event_type);
```

`blockchain_anchor` is deliberately **not** a column yet. It stays a model-only
field (always `null`) until Phase 5, when it gets added by migration. Adding it
now would mean a column that is null in every row for a full semester, and — more
importantly — a decision about whether the anchor is inside or outside the hash
preimage that we shouldn't make before the anchoring design exists.

---

## Design decisions and rationale

### 1. Hash formula

```
current_hash = SHA256(timestamp + event_type + canonical_json(event_data) + previous_hash)
```

The spec (§4) writes this as `Hash_N = SHA256(timestamp + data + Hash_{N-1})`.
Here `data` is `event_type + event_data`: folding the type into the preimage
means an attacker can't relabel a `file_encrypted` block as `benign_write`
while keeping the hash valid. Strictly stronger, same shape.

### 2. Canonical JSON — the important one

`event_data` arrives as a JSON object and is stored as TEXT. If we hashed a
freshly re-serialised dict at verify time, any difference in key order or
whitespace between write and read would look identical to tampering. So:

- `canonical_json()` (`database.py`) is the *only* place a dict becomes bytes:
  `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
- The block is hashed over exactly the text that is written to the row.
- Verification re-hashes **the stored string**, never a re-serialised object.

That makes false "tamper detected" results structurally impossible, which
matters because our target for false tamper alarms is zero.

### 3. Full 64-character hashes

SHA-256 hexdigests are stored at full width. The earlier integration stub
truncated to 32 chars; truncation halves collision resistance for no benefit
here. *Integration note for SH:* the dashboard already renders hashes through
`short_hash()`, so this is display-safe — but any test asserting `len(hash) == 32`
needs updating.

### 4. Genesis block

The first block's `previous_hash` is `"0" * 64` rather than a fixed magic
constant, so chain verification needs no special-casing beyond "block 1 points
at genesis".

### 5. Metadata only

No file contents, ever. Paths, hashes, entropy values, PIDs, usernames — the
things needed to prove *what happened* — but never the bytes it happened to.
This is the project's stated privacy principle (§1.5), and it also keeps the
ledger small enough for sub-50ms full-chain verification.

### 6. Append-only

There is no `UPDATE` or `DELETE` path in the service. The only write is an
append. Tampering therefore requires writing to the SQLite file directly, which
is exactly what TC-05 simulates and what verification catches.

---

## `event_type` / `event_data` contract

`event_data` is free-form JSON, so teammates aren't blocked on ledger changes to
log something new. Types in use so far:

| `event_type` | Emitted by | Typical `event_data` |
|---|---|---|
| `analysis` | Gateway `/analyze` | `{file_path, features, result, request_id}` |
| `file_encrypted` | Monitor / Response | `{file_path, process_id, user, entropy}` |
| `snapshot_created` | Recovery (SI, Phase 3) | `{snapshot_id, volume, created_at}` |
| `file_recovered` | Recovery (SI, Phase 4) | `{file_path, snapshot_id, integrity_verified}` |

**Request to AS/NI:** when you log an event about a file you have just hashed,
include that hash as `file_hash` in `event_data`. Recovery's integrity check
(Phase 4) verifies a restored file against the last hash the ledger holds for
that path — if no event ever carried one, recovery can restore the file but has
to report `integrity_verified: false` because it has nothing to compare against.

---

## Files

| File | Purpose |
|---|---|
| `models.py` | Pydantic models — `LedgerBlock`, request/response, error envelope |
| `database.py` | SQLite connection, schema, canonical JSON serialisation |
| `hash_chain.py` | `HashChainLedger` — append, verify, paginate (Phase 2) |
| `main.py` | FastAPI app and endpoints (Phase 2) |
| `app.py` | Compatibility shim re-exporting `main:app` |
| `tests/` | pytest suite |

Run instructions and the endpoint reference live in
[`README-SI.md`](../../README-SI.md) at the repo root.
