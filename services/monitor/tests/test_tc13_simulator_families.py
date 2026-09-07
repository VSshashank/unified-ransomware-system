"""TC-13 - Scenario A: every simulated ransomware family past a live Monitor.

Section 6.4.1: *"we executed 10 different ransomware simulators (e.g., RanSim).
Measured Result Placeholder: The system successfully detected and terminated
10/10 instances within 2 seconds. (To be replaced with real evidence)"*

This is the replacement. It now reports **13/13**, and the number is worth
reading with its history attached, because for most of this project's life it
read 8/10 and this file asserted the two misses by name so they could not
quietly become "10/10" in a later edit of a document:

    `partial`  intermittent encryption. A quarter of each file scrambled puts
               whole-file entropy at ~5.2 bits/byte against a 7.5 threshold, and
               an average cannot see it. Closed by scoring 4KB blocks
               separately - the objection at the time was that a .docx or PDF
               carries compressed blocks with the same profile, which is true,
               and is why the rule is gated on the file not being a
               structurally valid container.
    `spoofer`  a new .zip carrying a real ZIP header over ciphertext, with the
               original deleted. No prior reading on that path, so no rise; the
               container exemption then explained the entropy away. Closed by
               checking whether the ZIP structure is actually there - it costs
               four bytes to claim a format and an encoder to have one.

Three families were added afterwards, each written against a hole found by
reading the detector's source rather than by watching it fail:

    `strider`  strided intermittent encryption rather than a leading run, so
               that `partial` being caught cannot be an artefact of only ever
               looking at the front of a file.
    `grinder`  five sub-floor writes to flush the differential-entropy window,
               then ciphertext behind a ZIP header.
    `poisoner` high-entropy files written while training mode is learning, to
               raise the ceiling the encryption then hides under.

See `scripts/simulator_sweep.py` for the measurement and
`reports/simulator_families.json` for the recorded run.
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

# Empty, and it is an assertion rather than a deletion. A family that stops
# being caught has to fail a test rather than disappear from a list.
KNOWN_BLIND_SPOTS: set[str] = set()

# Which evidence each family is expected to be caught by. Asserting the signal
# and not just the flag is what stops a family from passing for the wrong
# reason - `grinder` is caught by structural validation even when the entropy
# floor has been flushed, so "detected" alone would hide a regression in the
# floor completely.
EXPECTED_SIGNALS = {
    "locker": "static_entropy",
    "silent": "entropy_rise",
    "copycat": "static_entropy",
    "partial": "partial_entropy",
    "headerspoof": "entropy_rise",
    "renamer": "static_entropy",
    "notedrop": "entropy_rise",
    "slowburn": "entropy_rise",
    "staged": "entropy_rise",
    "spoofer": "structural_mismatch",
    "strider": "partial_entropy",
    "grinder": "entropy_rise",
    "poisoner": "entropy_rise",
}


@pytest.fixture(scope="module")
def sweep():
    """One sweep for the whole module - it is the expensive part."""
    return {
        family: simulator_sweep.run_family(family, FILES_PER_FAMILY, SETTLE_SECONDS)
        for family in simulator_sweep._families()
    }


@pytest.mark.benchmark
def test_tc13_at_least_ten_families_are_simulated(sweep):
    """Section 6.4.1 says ten. Fewer than ten is not the scenario it describes."""
    assert len(sweep) >= 10, f"expected at least 10 families, got {sorted(sweep)}"
    assert set(sweep) == set(EXPECTED_SIGNALS), (
        "a family was added or removed without saying what should catch it: "
        f"{sorted(set(sweep) ^ set(EXPECTED_SIGNALS))}"
    )


@pytest.mark.benchmark
def test_tc13_every_family_is_detected_within_two_seconds(sweep):
    """The N/N, with the deadline section 6.4.1 states."""
    detected = {name for name, r in sweep.items() if r["detected"]}
    missed = set(sweep) - detected

    assert missed == KNOWN_BLIND_SPOTS, (
        f"the set of undetected families changed: {sorted(missed)}. "
        f"If it grew, that is a regression. If it shrank, update this test, "
        f"docs/test_cases.md and APPROACH.md section 8."
    )

    late = {
        name: sweep[name]["detection_seconds"]
        for name in detected
        if not sweep[name]["within_2s"]
    }
    assert not late, f"detected but outside the 2s deadline: {late}"


@pytest.mark.benchmark
def test_tc13_every_family_is_caught_by_the_evidence_it_is_meant_to_test(sweep):
    """A family caught for the wrong reason has stopped testing what it exists for."""
    wrong = {
        name: result["signals"]
        for name, result in sweep.items()
        if result["signals"] != [EXPECTED_SIGNALS[name]]
    }
    assert not wrong, f"caught, but not by the expected evidence: {wrong}"


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
@pytest.mark.parametrize("family", ["partial", "strider"])
def test_tc13_intermittent_encryption_stays_below_the_entropy_threshold(sweep, family):
    """Both intermittent families are caught *without* whole-file entropy helping.

    Without this, the detection assertion above would still pass if the
    simulator broke and started writing fully encrypted files - which would make
    the block profile look like it was working when it had never been consulted.
    """
    result = sweep[family]
    assert result["files_encrypted"] == FILES_PER_FAMILY
    assert 4.0 < result["mean_entropy"] < 7.5, (
        f"{family}'s entropy is {result['mean_entropy']}; the block profile only "
        "means anything while whole-file entropy stays under the threshold"
    )


@pytest.mark.benchmark
def test_tc13_header_spoofing_is_caught_by_differential_entropy(sweep):
    """`headerspoof` is the case the container exemption would otherwise wave through.

    It is detected because the rise is checked before the exemption. This is the
    test that fails if that ordering is ever swapped.
    """
    result = sweep["headerspoof"]
    assert result["detected"]
    assert result["files_flagged"] == result["files_encrypted"]
    assert result["verdicts"] == ["suspected_encryption"]


@pytest.mark.benchmark
def test_tc13_a_forged_container_is_caught_with_no_history_to_help(sweep):
    """`spoofer` is the same evasion with the one thing that made it work.

    It writes a *new* path, so there is no prior reading to rise from and
    differential entropy has nothing to say. Only the structure does.
    """
    result = sweep["spoofer"]
    assert result["detected"]
    assert result["signals"] == ["structural_mismatch"]
    assert result["files_flagged"] == result["files_encrypted"]


@pytest.mark.benchmark
def test_tc13_poisoning_the_training_baseline_teaches_it_nothing(sweep):
    """`poisoner` writes its ceiling-raisers during a real training window.

    The window is opened with the production dwell requirement, so files created
    seconds before it closes are recorded as candidates and never promoted. An
    empty `training_learned` is the measurement: the ceiling the attacker tried
    to buy does not exist, and the encryption that follows is not suppressed.
    """
    result = sweep["poisoner"]
    assert result["training_learned"] == [], (
        f"the baseline learned {result['training_learned']} from files created "
        "during the window"
    )
    assert result["detected"]
    assert result["files_suppressed"] == 0
    assert result["files_flagged"] == result["files_encrypted"]


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
    """Reversibility is what makes any of these safe to run - all of them."""
    broken = [name for name, r in sweep.items() if not r["restore_round_trips"]]
    assert not broken, f"--restore did not round-trip: {broken}"
