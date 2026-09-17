"""Keep the Monitor's fan-out logic; replace the sockets underneath it.

`services/monitor/pipeline.py` decides *what* gets recorded and *when*: which
events reach the ledger, when a benign first sighting is worth a baseline hash,
when a governance decision is chained, and - in `trigger_response` - the rule
that only a `CERTAIN` attribution may ask for a termination. That logic is the
Monitor's and it is load-bearing. It should not be reimplemented here, and the
whole of it funnels through one function, `pipeline._post(client, base_url,
path, payload)`.

So this replaces that one function. Every decision above it runs unchanged; the
ledger leg lands in SQLite in this process instead of crossing a socket to port
8003, and the response leg reports the action the agent already took instead of
asking a container that cannot see host PIDs to take a second one.

The ML leg is off the protection path by construction. Detection to suspend is
a 100 ms budget and a classifier round trip does not belong inside it. If
`ml_url` is configured the call is made over real HTTP by the pipeline worker,
which runs on a background thread; if it is not, the hop reports itself as
unavailable, which is what the pipeline already does for a service that is
down.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


class InProcessTransport:
    """A drop-in for `pipeline._post` that never leaves the process.

    Call signature is the pipeline's, not a convenience of ours:
    ``(client, base_url, path, payload) -> dict | None``. Returning ``None`` is
    the pipeline's established way of saying "that hop did not happen", so an
    unreachable leg degrades exactly as it always did.
    """

    def __init__(self, ledger, responder=None, ml_post: Callable | None = None,
                 on_block: Callable[[str, dict], None] | None = None) -> None:
        self.ledger = ledger
        self.responder = responder
        self.ml_post = ml_post
        #: Called with (event_type, event_data) after a block is committed.
        #: The agent uses it to keep its baseline-entropy cache current from
        #: the writes it is already making, instead of reading the chain back
        #: on the detection path. Never called for a write that failed, so the
        #: cache cannot claim a baseline the chain does not hold.
        self.on_block = on_block
        self.calls: list[tuple[str, str]] = []

    def __call__(self, client, base_url: str, path: str, payload: dict) -> dict | None:
        self.calls.append((base_url, path))

        if path == "/ledger/log":
            return self._ledger(payload)
        if path == "/response/trigger":
            return self._response(payload)
        if path == "/predict":
            return self._predict(client, base_url, path, payload)

        logger.warning("no in-process route for %s%s; treating the hop as "
                       "unavailable rather than falling back to HTTP",
                       base_url, path)
        return None

    # -- legs ---------------------------------------------------------------

    def _ledger(self, payload: dict) -> dict | None:
        try:
            block = self.ledger.chain.add_block(payload["event_type"],
                                                payload["event_data"])
        except Exception as exc:  # noqa: BLE001
            # The pipeline treats None as "the ledger did not take it" and
            # carries on. Losing an audit line is bad; dropping the response
            # because the audit line failed is worse.
            logger.error("direct ledger write failed for %s: %s",
                         payload.get("event_type"), exc)
            return None
        if self.on_block is not None:
            try:
                self.on_block(payload["event_type"], payload["event_data"])
            except Exception:  # noqa: BLE001 - a cache is not worth a lost write
                logger.exception("on_block hook failed for %s",
                                 payload.get("event_type"))
        return {"block_id": block["block_id"],
                "current_hash": block["current_hash"],
                "timestamp": block["timestamp"]}

    def _response(self, payload: dict) -> dict | None:
        """Report what the agent already did about this incident.

        The suspend happens synchronously on the detection path, because the
        pipeline's fan-out runs on a background thread and a response that
        waits for a queue is not a response inside 100 ms. By the time this leg
        runs, the decision is made; asking for a second action here would mean
        acting twice on one event.
        """
        incident = payload.get("incident_id")
        if self.responder is None or not incident:
            return None
        recorded = self.responder.recorded(incident)
        if recorded is None:
            return None
        return {
            **recorded,
            "requested_action": payload.get("action_required"),
            "note": "performed in-process by urds-agent before this record was "
                    "written; the Response service was not called",
        }

    def _predict(self, client, base_url: str, path: str, payload: dict) -> dict | None:
        if self.ml_post is None:
            return None
        return self.ml_post(client, base_url, path, payload)


def install(pipeline_module, transport: InProcessTransport) -> Callable:
    """Swap the transport in, returning the original so it can be restored."""
    original = pipeline_module._post
    pipeline_module._post = transport
    return original


def restore(pipeline_module, original: Callable) -> None:
    pipeline_module._post = original
