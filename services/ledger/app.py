"""Compatibility shim.

The real service is in main.py, per the SI deliverable layout. This module keeps
`uvicorn app:app` working for anything still pointing at the old entrypoint
(the placeholder stub this replaced).
"""

from main import app

__all__ = ["app"]
