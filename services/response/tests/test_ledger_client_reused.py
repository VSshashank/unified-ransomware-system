"""Defect 22, second half: a refused kill cost a TLS context.

R16 in the 2026-10-05 VM test: the Monitor's escalations for a PID that was
already dead went out 0.30-0.38 s apart, each refused ("PID ... does not
exist"). Measured in-process on the VM (perf_counter, 8 runs, the real handler
against a local ledger stub and a PID that does not exist): the terminate
handler took a median 252 ms to refuse; `actions.guard` 27 ms of it, and the
ledger write 200 ms - because `log_action` called `httpx.post`, which builds a
new `httpx.Client` (an SSL context and certifi's CA bundle) for every block.
The same POST on a reused client took 5 ms.

Here every `httpx.Client` built while the Response service writes blocks is
counted, with a mock transport standing in for the ledger.
"""

import httpx
import psutil
import pytest

import app as response_app


@pytest.fixture
def constructions(monkeypatch):
    built: list[httpx.Client] = []
    posted: list[str] = []

    def ledger(request: httpx.Request) -> httpx.Response:
        posted.append(str(request.url))
        return httpx.Response(201, json={"block_id": len(posted)})

    original = httpx.Client.__init__

    def counting_init(self, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(ledger)
        original(self, *args, **kwargs)
        built.append(self)

    monkeypatch.setattr(httpx.Client, "__init__", counting_init)
    # Start from no shared client, so one built earlier in the session is not
    # mistaken for reuse.
    monkeypatch.setattr(response_app, "_LEDGER_CLIENT", None, raising=False)
    yield built, posted
    client = getattr(response_app, "_LEDGER_CLIENT", None)
    if client is not None:
        client.close()


def _dead_pid() -> int:
    pid = 999_983
    while psutil.pid_exists(pid):
        pid -= 1
    return pid


def test_ledger_writes_share_one_http_client(constructions):
    built, posted = constructions

    blocks = [response_app.log_action("response_action", {"n": n}) for n in range(5)]

    assert [b["block_id"] for b in blocks] == [1, 2, 3, 4, 5]
    assert all(url.endswith("/ledger/log") for url in posted)
    assert len(built) == 1, f"{len(built)} httpx clients built for {len(posted)} ledger writes"


def test_refusing_a_dead_pid_builds_no_client_per_request(constructions):
    built, posted = constructions
    request = response_app.TerminateRequest(
        process_id=_dead_pid(), incident_id="inc_r16", reason="escalated",
        attribution_confidence="certain", attribution_source="fake-4663",
    )

    statuses = [response_app.terminate(request).status_code for _ in range(4)]

    assert statuses == [409, 409, 409, 409]
    assert len(posted) == 4  # every refusal is still on the chain
    assert len(built) <= 1, f"{len(built)} httpx clients built for 4 refusals"
