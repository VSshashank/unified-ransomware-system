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