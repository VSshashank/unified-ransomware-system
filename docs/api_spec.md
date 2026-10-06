> **SUPERSEDED — do not use. See [`openapi/gateway.yaml`](openapi/gateway.yaml).**
>
> This is the Phase 2 sketch of the contracts, kept for history. It disagrees
> with what the services actually implement: the feature field is
> `shannon_entropy`, not `entropy`, and the real FeatureSet carries six fields,
> not three. `openapi/gateway.yaml` is the authoritative contract, and the
> gateway suite asserts the implementation matches it in both directions, so it
> cannot drift.

# API Rules (Contracts)

## 1. Monitor Service Rules (What AS sends to SH)
When the Monitor sees a file change, it MUST send this JSON to the Gateway:
{
  "watch_path": "/path/to/monitor",
  "file_patterns": ["*.doc", "*.pdf"]
}

## 2. ML Engine Rules (What SH sends to NI)
When we need a prediction, Gateway sends features to ML Engine:
{
  "features": {
    "entropy": 7.89,
    "file_size": 1048576,
    "magic_bytes": "4D5A"
  }
}

## 3. ML Response Rules (What NI sends back)
The ML Engine MUST reply with:
{
  "prediction": "ransomware",
  "confidence": 0.94
}

## 4. Response: suspend and resume under a lease (defect 26, F2b)

Added after this file was superseded, because the suspend contract was fixed
here first for two parallel work packages. `openapi/gateway.yaml` carries the
same contract with full schemas and stays authoritative.

The design: the Monitor suspends a sole writer early, on a `suspend_authorised`
gate of its own, then either kills it at the horizon (`kill_authorised`,
unchanged) or resumes it. **That Monitor side was not built** (FIXES.md,
defect 26); today only an operator calls these routes, through the gateway.
The Response service holds every suspension as a **lease** that ends on its
own. It evaluates **no gate** itself.

```
POST /response/suspend   {process_id, incident_id, lease_seconds, reason,
                          attribution_confidence, attribution_source,
                          attribution_reason, image?, started_at?, gate?}
  200 {lease_id, process_id, suspended: true, expires_at, already_held: bool}
  409 {code, message}   refused: system image, the Monitor/Response/their ancestors,
                         PID gone or reused (create-time/image mismatch)
POST /response/resume    {lease_id | process_id, incident_id, reason}
  200 {lease_id, resumed: true, reason}      (idempotent: resuming a released lease is 200, resumed: false)
POST /response/terminate  (unchanged; additionally accepts lease_id and releases that lease)
GET  /response/leases    -> [{lease_id, process_id, incident_id, expires_at, state}]
ledger blocks: process_suspended, process_resumed (with reason), joined to the
terminate block by lease_id and incident_id
```

How the Response service implements it (`services/response/leases.py`,
`actions.py`, `lease_watchdog.py`):

- **One lease per PID.** A second suspend of a held PID suspends nothing and
  returns the same lease with `already_held: true`. Suspension nests on
  Windows (`NtSuspendProcess`); a second suspend would need a second resume.
- `lease_seconds` must be a finite number above 0 (`NaN`/`Infinity` is a
  400) and is capped at `RESPONSE_LEASE_MAX_SECONDS` (default 10). A caller
  should ask for about the horizon (1.5 s) plus a margin.
- Once the Response service has begun to shut down, every suspend is refused
  (`SHUTTING_DOWN`): nothing would be left to end the lease.
- **Every lease ends**, in one of four states: `resumed` (by `/resume`, by
  expiry, or at Response shutdown), `terminated` (by `/terminate`, which
  closes the lease without resuming), or `gone` (the process exited). If the
  Response process is killed outright, a watchdog child resumes whatever was
  still held. A watchdog that is configured but not running refuses suspends
  (`WATCHDOG_UNAVAILABLE`).
- **`started_at`** is the process's creation time (epoch seconds or ISO-8601).
  A live process created after it, beyond 50 ms, holds a reused PID. **At least
  one of `image` and `started_at` must be checkable**, or the suspend is
  refused (`IDENTITY_UNPROVEN`).
- **The Monitor's PID** is configured as `URDS_MONITOR_PID`: positive
  integers separated by spaces, commas or semicolons. It and its ancestors are
  refused. A value that is set but does not parse refuses **every** suspend
  (`MONITOR_PID_INVALID`) rather than protecting nothing. When it is unset,
  the Response service cannot tell which process is the Monitor.
- **409 body:** the standard error envelope (`error.code`, `error.message`)
  with `code` and `message` repeated at the top level. Codes: RESERVED_PID,
  RESPONSE_OR_ANCESTOR, SYSTEM_PROCESS, PID_GONE, NOT_INSPECTABLE,
  MONITOR_OR_ANCESTOR, LEASE_WATCHDOG, PID_REUSED, IDENTITY_UNPROVEN,
  NOT_ATTRIBUTED, PID_NAMESPACE_ISOLATED, WATCHDOG_UNAVAILABLE, NOT_PERMITTED,
  MONITOR_PID_INVALID, SHUTTING_DOWN, LEASE_STATE_UNCERTAIN (a held PID's
  handle reports it gone and its start time cannot be read to tell whether it
  is the same process: refused rather than risk a second, nested suspend).
- **Ledger.** `process_suspended` is written for a suspension and for every
  refusal (`outcome: suspended | refused`, `suspended: true | false`, `code`).
  `process_resumed` is written whenever a lease ends other than by a kill
  (`outcome: resumed | process_gone`, `reason`, `requested_by: caller |
  lease_expiry | shutdown | atexit`). Both carry the PID together with **what
  the caller claimed** allowed it, recorded as the caller's:
  `attribution_confidence`, `attribution_source`, `attribution_reason`,
  `attribution_supplied_by: "caller"`, `gate` (the request's `gate`, verbatim,
  or `null`), `gate_verified: false` (the Response service cannot verify a
  gate) and `gate_reason` (`no gate supplied (operator request)` when there
  was none). Until 2026-10-06 the service wrote `gate: "suspend_authorised"`
  itself on every block - a gate nobody had evaluated (review finding R8c).
  A `response_action` terminate block carries `lease_id` and
  `lease_released`.
- **Docker.** In Compose, Response runs in its own PID namespace and cannot
  suspend a host PID. It refuses with `PID_NAMESPACE_ISOLATED` and records the
  refusal; `RESPONSE_PID_NAMESPACE=host` declares a container started with
  `pid: host`.
