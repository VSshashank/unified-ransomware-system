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