"""Start the Monitor service watching the shared watched_files/ mount.

The Monitor boots idle (`monitoring: false`) after every `docker-compose up`,
so no file event fires until something calls POST /monitor/start. Run this
once per stack restart, before running the ransomware simulator, or the
dashboard will show no activity no matter what the simulator does.
"""
from datetime import datetime, timedelta, timezone

import requests
from jose import jwt

GATEWAY_URL = "http://localhost:8000"
JWT_SECRET = "dev-only-change-me"  # matches docker-compose.yml's default


def make_admin_token() -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "demo-cli",
        "role": "admin",
        "tier": "enterprise",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=2)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def main() -> int:
    token = make_admin_token()
    response = requests.post(
        f"{GATEWAY_URL}/monitor/start",
        headers={"Authorization": f"Bearer {token}"},
        json={"watch_path": "/watch", "recursive": True, "file_patterns": ["*"]},
        timeout=5,
    )
    print(response.status_code, response.json())
    return 0 if response.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
