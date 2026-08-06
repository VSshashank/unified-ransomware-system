import os
import sys
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_DIR.parents[1]

# Flat imports, matching the container layout.
sys.path.insert(0, str(SERVICE_DIR))

# Point the service at the repo's models/ directory instead of the container's
# /models mount.
os.environ.setdefault("MODEL_DIR", str(REPO_ROOT / "models"))
os.environ.setdefault("MODEL_PATH", str(REPO_ROOT / "models" / "xgboost_model.pkl"))
os.environ.setdefault(
    "BEHAVIORAL_MODEL_PATH", str(REPO_ROOT / "models" / "behavioral_model.pkl")
)
