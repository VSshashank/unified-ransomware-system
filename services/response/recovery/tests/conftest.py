import sys
from pathlib import Path

# `services/response` on the path so `import recovery` resolves the same way it
# does inside the Response container.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
