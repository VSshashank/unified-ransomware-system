import os
import sys
from pathlib import Path

# The service modules sit one level up and are imported flat (matching how they
# are laid out in the container), so put that directory on the path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# This directory, so `_arms` - the shared scoring helper for TC-14…TC-19 - is
# importable. Pytest's default "prepend" import mode adds it implicitly, so this
# is redundant there and not redundant anywhere else: it is what lets the file be
# imported when the suite is invoked with `--import-mode=importlib`, or from a
# working directory other than this service's.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# scripts/synthetic_corpus.py builds the structurally valid sample files these
# tests measure against. It lives at the repository root rather than in the
# service because the training corpus in src/ has to build the same files from
# the same code - two copies of "what a real PNG looks like" is how the training
# corpus and the benchmark corpus ended up disagreeing with the detector. It is
# a test and training dependency only; nothing the container runs imports it.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

# Unit tests must not fan out to ML/ledger/response - those are exercised in the
# integration pass, against real running services.
os.environ.setdefault("PIPELINE_ENABLED", "false")
