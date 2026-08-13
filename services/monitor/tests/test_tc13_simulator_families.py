"""TC-13 - Scenario A: ten ransomware families past a live Monitor.

Section 6.4.1: *"we executed 10 different ransomware simulators (e.g., RanSim).
Measured Result Placeholder: The system successfully detected and terminated
10/10 instances within 2 seconds. (To be replaced with real evidence)"*

This is the replacement, and it does not report 10/10. It reports **8/10**, and
asserts the two misses by name so they cannot quietly become "10/10" in a later
edit of a document. See `scripts/simulator_sweep.py` for the measurement and
`reports/simulator_families.json` for the recorded run.

Why the two misses are misses on purpose
----------------------------------------
`partial` is intermittent encryption (LockBit 3, BlackCat): a quarter of each
file is scrambled, so whole-file entropy lands at ~5.2 bits/byte against a 7.5
threshold. Catching it needs per-block entropy, which also fires on the
compressed blocks inside any .docx or PDF - trading a measured 0% false-positive
rate, which is a graded criterion, for a technique the reference document never
asks for.

`spoofer` writes a *new* `.zip` carrying a real ZIP header over ciphertext and
deletes the original. With no prior reading on that path there is no entropy rise
to catch, and what remains - a new archive appearing while a document
disappears - is byte-for-byte what "compress a file and delete the original"
looks like. Separating the two needs to know *which process* did both, and
process attribution does not exist here (see APPROACH.md section 8).

Both are therefore honest limits of whole-file entropy, not tuning that was left
undone. If either starts being detected, this test fails and should be rewritten.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import simulator_sweep  # noqa: E402

# Fewer files than the recorded sweep: this asserts the behaviour, the script
# produces the evidence. `slowburn` paces itself at 800ms per file, so the count
# is what decides how long this test takes.
FILES_PER_FAMILY = 4
SETTLE_SECONDS = 1.0

KNOWN_BLIND_SPOTS = {"partial", "spoofer"}


@pytest.fixture(scope="module")
def sweep():
    """One sweep for the whole module - it is the expensive part."""
    return {
        family: simulator_sweep.run_family(family, FILES_PER_FAMILY, SETTLE_SECONDS)
        for family in simulator_sweep._families()
    }


@pytest.mark.benchmark
def test_tc13_ten_families_are_simulated(sweep):
    """Section 6.4.1 says ten. Fewer than ten is not the scenario it describes."""
    assert len(sweep) == 10, f"expected 10 families, got {sorted(sweep)}"


@pytest.mark.benchmark
def test_tc13_eight_of_ten_families_are_detected_within_two_seconds(sweep):
    """The honest N/10, with the deadline section 6.4.1 states."""
    detected = {name for name, r in sweep.items() if r["detected"]}
    missed = set(sweep) - detected

    assert missed == KNOWN_BLIND_SPOTS, (
        f"the set of undetected families changed: {sorted(missed)}. "
        f"If it shrank, update this test, docs/test_cases.md and APPROACH.md section 8."
    )

    late = {
        name: sweep[name]["detection_seconds"]
        for name in detected
        if not sweep[name]["within_2s"]
    }
    assert not late, f"detected but outside the 2s deadline: {late}"


@pytest.mark.benchmark
def test_tc13_every_detected_family_is_caught_on_every_file(sweep):
    """A family caught on one file in eight would still count as "detected"."""
    partial = {
        name: f"{r['files_flagged']}/{r['files_encrypted']}"
        for name, r in sweep.items()
        if r["detected"] and r["files_flagged"] != r["files_encrypted"]
    }
    assert not partial, f"detected on only some files: {partial}"


@pytest.mark.benchmark
def test_tc13_intermittent_encryption_stays_below_the_entropy_threshold(sweep):
    """`partial` is missed for the stated reason, not for an unrelated one.

    Without this, the blind-spot assertion above would still pass if `partial`
    started failing because the simulator broke rather than because whole-file
    entropy cannot see it.
    """
    result = sweep["partial"]
    assert result["files_encrypted"] == FILES_PER_FAMILY
    assert 4.0 < result["mean_entropy"] < 7.5, (
        f"partial's entropy is {result['mean_entropy']}; the blind spot is only "
        "explained by entropy landing between plaintext and ciphertext"
    )


@pytest.mark.benchmark
def test_tc13_header_spoofing_is_caught_by_differential_entropy(sweep):
    """`headerspoof` is the case the container exemption would otherwise wave through.

    It is detected only because the rise is checked before the exemption. This is
    the test that fails if that ordering is ever swapped.
    """
    result = sweep["headerspoof"]
    assert result["detected"]
    assert result["files_flagged"] == result["files_encrypted"]
    assert result["verdicts"] == ["suspected_encryption"]


@pytest.mark.benchmark
def test_tc13_a_ransom_note_is_not_itself_a_false_positive(sweep):
    """`notedrop` leaves a plaintext note beside every file it encrypts.

    The note is low-entropy text. Flagging it would be a false positive in every
    directory the family touches, so it is asserted as benign while the files
    around it are asserted as caught.
    """
    result = sweep["notedrop"]
    assert result["detected"]
    assert result["collateral_events_flagged"] == 0, "the ransom note was flagged as an attack"


@pytest.mark.benchmark
def test_tc13_every_family_restores_byte_for_byte(sweep):
    """Reversibility is what makes any of these safe to run - all ten, not eight."""
    broken = [name for name, r in sweep.items() if not r["restore_round_trips"]]
    assert not broken, f"--restore did not round-trip: {broken}"
