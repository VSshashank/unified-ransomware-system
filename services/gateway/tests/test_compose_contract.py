"""docker-compose.yml against Listings 3.20 and 3.21 - SH.

Listing 3.20 specifies the deployment; Listing 3.21 specifies the commands that
deployment must support. The two contradict each other - 3.20 pins
`container_name: ransomware_ml` and publishes a fixed host 8002, and 3.21 asks
for `--scale ml_engine=3`, which neither of those permits. The repo resolves the
contradiction in favour of the command working, and these tests hold that
resolution in place: the settings that block scaling are easy to reintroduce by
copying 3.20 verbatim, and the failure mode is a warning on stdout that leaves
one replica running and looks like success.
"""

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

COMPOSE_PATH = Path(__file__).resolve().parents[3] / "docker-compose.yml"

SCALABLE_SERVICE = "ml_engine"


@pytest.fixture(scope="module")
def compose() -> dict:
    if not COMPOSE_PATH.is_file():
        pytest.skip(f"{COMPOSE_PATH} not present")
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def test_compose_parses_and_defines_every_documented_service(compose):
    services = compose["services"]
    for name in ("monitor", "ml_engine", "ledger", "response", "gateway"):
        assert name in services, f"Listing 3.20 names {name}"


def test_scalable_service_has_no_container_name(compose):
    """Docker refuses to scale a service with a fixed container name."""
    assert "container_name" not in compose["services"][SCALABLE_SERVICE], (
        "container_name on ml_engine makes `docker compose up -d --scale "
        "ml_engine=3` (Listing 3.21) refuse to scale"
    )


def test_scalable_service_publishes_no_fixed_host_port(compose):
    """Three replicas cannot all bind the same host port.

    An ephemeral mapping ("127.0.0.1::8002") is what allows the count to vary;
    a fixed one ("127.0.0.1:8002:8002") makes the second replica fail to start.
    """
    for mapping in compose["services"][SCALABLE_SERVICE].get("ports", []):
        parts = str(mapping).split(":")
        # host:container -> 2 parts, ip:host:container -> 3 parts. An ephemeral
        # mapping leaves the host field empty, so the split still has 3 parts
        # but the middle one is "".
        assert parts[-2] == "", (
            f"ml_engine publishes fixed host port in {mapping!r}, which stops "
            "the service scaling past one replica"
        )


def test_ml_engine_keeps_listing_3_20_resource_limits(compose):
    limits = compose["services"][SCALABLE_SERVICE]["deploy"]["resources"]["limits"]
    assert str(limits["cpus"]) == "2"
    assert str(limits["memory"]) == "2G"


def test_services_reach_the_ml_engine_by_dns_not_by_container_name(compose):
    """With replicas, the compose DNS name is the only address that resolves.

    Hardcoding a container name here would work with one replica and silently
    pin every request to that one replica with three.
    """
    for service in ("gateway", "monitor"):
        environment = compose["services"][service]["environment"]
        ml_url = next(entry for entry in environment if entry.startswith("ML_URL="))
        assert "ml_engine:8002" in ml_url, f"{service} must address ml_engine by service name"
