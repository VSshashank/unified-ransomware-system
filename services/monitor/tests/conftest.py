import os
import sys
from pathlib import Path

# The service modules sit one level up and are imported flat (matching how they
# are laid out in the container), so put that directory on the path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Unit tests must not fan out to ML/ledger/response - those are exercised in the
# integration pass, against real running services.
os.environ.setdefault("PIPELINE_ENABLED", "false")
