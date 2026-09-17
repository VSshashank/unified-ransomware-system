"""urds-agent: the protection path, running natively on the host.

The six services stay where they are and keep doing their work. What moves is
*where the protection path executes*, and it moves for one reason: the Response
service runs in a container with its own PID namespace, so a correct host PID
still cannot be suspended or killed from inside it. That is the single defect
blocking every operational claim in the project, and no amount of care inside
the container fixes it.

So this package rehosts the hot path and rewrites nothing. It **imports**
`services/monitor/detection.py`, `services/monitor/attribution.py`,
`services/response/actions.py` and `services/response/recovery/` rather than
copying them: one implementation, one test suite, one place a bug gets fixed.
See `agent.imports`, which is deliberately strict about proving that the module
it loaded is the file it meant to load.

The hot path is in-process. detect -> attribute -> suspend crosses no socket,
because a 100 ms budget spent partly on HTTP to localhost is a budget spent on
the wrong thing.

Docker remains supported and is no longer required. Compose is the
cross-platform demonstration and CI path; it is not the protection path.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
