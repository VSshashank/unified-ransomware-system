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

The Monitor suspends a sole writer early, on its `suspend_authorised` gate,
then either kills it at the horizon (`kill_authorised`, unchanged) or resumes
it. The Response service holds every suspension as a **lease** that ends on
its own.

```
POST /response/suspend   {process_id, incident_id, lease_seconds, reason,
                          attribution_confidence, attribution_source,
                          attribution_reason, image?, started_at?}
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
- `lease_seconds` is capped at `RESPONSE_LEASE_MAX_SECONDS` (default 10). The
  Monitor should ask for about the horizon (1.5 s) plus a margin.
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
- **The Monitor's PID** is configured as `URDS_MONITOR_PID`
  (comma-separated). It and its ancestors are refused. When it is unset, the
  Response service cannot tell which process is the Monitor, and only the
  Monitor's own gate keeps it from naming itself.
- **409 body:** the standard error envelope (`error.code`, `error.message`)
  with `code` and `message` repeated at the top level. Codes: RESERVED_PID,
  RESPONSE_OR_ANCESTOR, SYSTEM_PROCESS, PID_GONE, NOT_INSPECTABLE,
  MONITOR_OR_ANCESTOR, LEASE_WATCHDOG, PID_REUSED, IDENTITY_UNPROVEN,
  NOT_ATTRIBUTED, PID_NAMESPACE_ISOLATED, WATCHDOG_UNAVAILABLE, NOT_PERMITTED.
- **Ledger.** `process_suspended` is written for a suspension and for every
  refusal (`outcome: suspended | refused`, `suspended: true | false`, `code`).
  `process_resumed` is written whenever a lease ends other than by a kill
  (`outcome: resumed | process_gone`, `reason`, `requested_by: caller |
  lease_expiry | shutdown | atexit`). Both carry the PID **with** the gate
  that allowed it: `attribution_confidence`, `attribution_source`,
  `attribution_reason`, `gate: "suspend_authorised"` (C-16). A
  `response_action` terminate block carries `lease_id` and `lease_released`.
- **Docker.** In Compose, Response runs in its own PID namespace and cannot
  suspend a host PID. It refuses with `PID_NAMESPACE_ISOLATED` and records the
  refusal; `RESPONSE_PID_NAMESPACE=host` declares a container started with
  `pid: host`.
