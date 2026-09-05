"""What capability an attacker actually needs, measured per strategy - AS + NI.

Item P5.4, Chapter 9 §9.4.1, artefact register §9.8 →
reports/capability_calibration.json.

`services/monitor/admissibility.py` assigns every detection signal an avoidance
cost and every suppression a forgery cost on a four-point ordinal ladder. Those
numbers were assigned by hand and defended in prose;
`docs/CAPABILITY_GOVERNED_EXCEPTIONS.md` says so outright - *"The scale is a
modelling choice, not a measurement."* This script is the measurement.

The ladder, quoted from admissibility.py:68-71
----------------------------------------------
    0  NEGLIGIBLE  bytes the attacker chooses freely: a filename, a magic number
    1  LOW         a location the attacker can already write to
    2  MODERATE    well-formed output the attacker must actually produce
    3  HIGH        a secret or a preimage the attacker cannot produce at all

How a level is measured rather than asserted
--------------------------------------------
For each strategy the cheapest attack that defeats it is *built and run*, and
what it took to build is recorded as operational facts, not as a judgement:

    third_party_dependencies    packages the attacker had to install
    ships_an_encoder            did the attacker write format-producing code
    format_specific_knowledge   did the attack need to know the format's layout
    attacker_statements         how many statements the attack is
    requires_secret_or_preimage is the attack infeasible rather than merely hard
    write_location_only         is the whole attack "write somewhere allowed"

The level is then derived from those facts. Two derivations are run:

    `assign_level`   the primary mapping, written against the rung definitions
    `rederive_level` a second mapping over the same recorded facts, written to
                     a different decision order

Where they agree the level is recorded with its source trail. Where they
disagree the level is recorded **unresolved** and D2's conservative reading is
taken.

On the second-reviewer rule, stated plainly
-------------------------------------------
§9.15 requires no capability level to be accepted on one member's word, with the
ring AS↔NI. Both derivations here were written in the same session by the same
author. They re-derive the level from the recorded operational facts rather than
from the first conclusion, which is what the protocol asks a reproducing member
to do - but they are **not an independent human reviewer**, and this report says
so in every record. Every level is therefore marked
`reproduction.independent_human_reviewer: false`.

    .venv\\Scripts\\python.exe scripts/capability_calibration.py

Writes the report only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import pickle
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"

sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

import admissibility  # noqa: E402
import containers  # noqa: E402
import detection  # noqa: E402
import suppression as suppression_module  # noqa: E402

PAYLOAD_BYTES = 120_000
LEVEL_NAMES = admissibility.COST_NAMES


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def deterministic_payload(tag: str, size: int = PAYLOAD_BYTES) -> bytes:
    """Ciphertext-shaped bytes that are the same on every run.

    A real encryptor would use a cipher; what matters to every measurement here
    is the byte distribution, and a SHAKE stream is flat and reproducible. Using
    os.urandom would make the artefact hashes in the source trail meaningless.
    """
    return hashlib.shake_256(tag.encode()).digest(size)


# ------------------------------------------------------------------ scoring


def score(path: Path, entropy_delta: float | None = None) -> dict:
    size = path.stat().st_size
    head, tail = detection.sample_file(str(path), size)
    entropy, statistics = detection.measure(head)
    magic = detection.read_magic(str(path))
    container = detection.identify_container(magic)
    tri_state = containers.validate_container(head, tail, container, size)
    verdict = detection.classify(
        str(path),
        entropy,
        magic,
        detection.DEFAULT_ENTROPY_THRESHOLD,
        readable=True,
        entropy_delta=entropy_delta,
        container_valid=tri_state,
        statistics=statistics,
    )
    return {
        "entropy": verdict["entropy"],
        "container_format": container,
        "container_status": containers.container_status(head, tail, container, size),
        "validate_container": tri_state,
        "verdict": verdict["verdict"],
        "suspicious": verdict["suspicious"],
        "signal": verdict["signal"],
    }


# ------------------------------------------------------- level derivation


def assign_level(facts: dict) -> int:
    """Primary derivation, in the order the rung definitions are written.

    Read top down: a preimage is HIGH; work the attacker must actually do to
    produce well-formed output is MODERATE; choosing a location is LOW;
    choosing bytes is NEGLIGIBLE.
    """
    if facts["requires_secret_or_preimage"]:
        return admissibility.HIGH
    if facts["ships_an_encoder"] or facts["format_specific_knowledge"]:
        return admissibility.MODERATE
    if facts["write_location_only"]:
        return admissibility.LOW
    if facts["third_party_dependencies"]:
        # Installing a package is real work, but it is not the attacker
        # *producing* well-formed output - the package does that. It sits above
        # choosing bytes and below shipping an encoder.
        return admissibility.LOW
    return admissibility.NEGLIGIBLE


def rederive_level(facts: dict) -> int:
    """Second derivation over the same recorded facts, bottom up.

    Deliberately a different decision order from `assign_level`: start at the
    cheapest rung and climb only when a fact forces it. Two orders over the same
    facts should land on the same rung; where they do not, the level is
    contestable and D2 says so.
    """
    level = admissibility.NEGLIGIBLE
    if facts["write_location_only"]:
        level = max(level, admissibility.LOW)
    if facts["third_party_dependencies"]:
        level = max(level, admissibility.LOW)
    if facts["format_specific_knowledge"]:
        level = max(level, admissibility.MODERATE)
    if facts["ships_an_encoder"]:
        level = max(level, admissibility.MODERATE)
    if facts["requires_secret_or_preimage"]:
        level = max(level, admissibility.HIGH)
    return level


# --------------------------------------- the plan's ladder, §5.2, five levels
#
# The four-point ladder above is `admissibility.py`'s, and it is the scale the
# deployed cost table is written on. NOVELTY_PROOF_PLAN.md §5.2 is a *different*
# scale with five rungs, and §9.1 makes the proof plan the governing method
# document, so both are derived here from the same recorded facts. They are not
# interchangeable and no level from one may be quoted as a level of the other.
#
#   0  direct attacker control      write bytes, choose a path, rename a file,
#                                   or prefix a recognised magic value
#   1  public primitive             a standard-library call, installed command
#                                   or mature package does it, with no
#                                   format-specific engineering
#   2  format-aware capability      additional format-specific structural or
#                                   semantic constraints must be satisfied
#   3  new engineering              material new implementation, or privileged
#                                   access outside the threat model
#   4  secret/preimage              a protected secret or a cryptographic
#                                   preimage is required
#
# The rung that moves things is 0 against 1. The code ladder prices "a location
# the attacker can already write to" at LOW, one rung above choosing bytes; the
# plan puts writing bytes and choosing a path on the same rung, Level 0, and
# reserves Level 1 for the case where a *library* did the work. That single
# difference is what makes `path` forgery tie with `static_entropy` avoidance
# under the plan and not under the code - and §6 of the plan asks specifically
# what the strict rule does to that tie.
PLAN_LEVEL_NAMES = {
    0: "direct attacker control",
    1: "public primitive",
    2: "format-aware capability",
    3: "new engineering or unavailable privilege",
    4: "secret/preimage",
}


def plan_level(facts: dict) -> int:
    """Primary derivation onto §5.2, top down in the order the rungs are written."""
    if facts["requires_secret_or_preimage"]:
        return 4
    if facts["ships_an_encoder"]:
        return 3
    if facts["format_specific_knowledge"]:
        return 2
    if facts["public_primitive"] or facts["third_party_dependencies"]:
        return 1
    # Everything left is bytes or a location the attacker chooses. §5.2 puts
    # "choose a path" in Level 0 explicitly, which is where the two ladders part
    # company: the code's LOW rung has no counterpart here.
    return 0


def plan_rederive_level(facts: dict) -> int:
    """Second derivation over the same facts, bottom up."""
    level = 0
    if facts["public_primitive"] or facts["third_party_dependencies"]:
        level = max(level, 1)
    if facts["format_specific_knowledge"]:
        level = max(level, 2)
    if facts["ships_an_encoder"]:
        level = max(level, 3)
    if facts["requires_secret_or_preimage"]:
        level = max(level, 4)
    return level


# §5.3 closes with calibration hypotheses, stated there as hypotheses "until the
# locked search record is complete". They are recorded against the strategies
# that test them, so the report says whether the plan's own guesses held.
PLAN_HYPOTHESES = {
    "static_entropy": (0, "an unvalidated magic prefix is Level 0"),
    "structural_mismatch": (
        1,
        "basic standard-library container generation is Level 1",
    ),
}


def record(
    strategy: str,
    kind: str,
    table_key: str,
    declared: int,
    attack: dict,
    facts: dict,
    measurement: dict,
    command: str,
    artefact_sha256: str | None,
) -> dict:
    primary = assign_level(facts)
    second = rederive_level(facts)
    agrees = primary == second

    plan_primary = plan_level(facts)
    plan_second = plan_rederive_level(facts)
    plan_agrees = plan_primary == plan_second
    plan_measured = (
        plan_primary
        if plan_agrees
        else (
            min(plan_primary, plan_second)
            if kind == "forgery"
            else max(plan_primary, plan_second)
        )
    )
    hypothesis = PLAN_HYPOTHESES.get(table_key)

    if agrees:
        measured = primary
        status = "reproduced"
    else:
        # D2: a level a second derivation cannot reproduce is unresolved, and
        # the policy takes the conservative reading. For a forgery cost the
        # conservative reading is the lower level (a suppression is trusted
        # less); for an avoidance cost it is the higher (a signal is treated as
        # harder to evade, so the alert survives more suppressions).
        measured = min(primary, second) if kind == "forgery" else max(primary, second)
        status = "unresolved"

    return {
        "strategy": strategy,
        "kind": kind,
        "cost_table_key": table_key,
        "cost_table_file": "services/monitor/admissibility.py",
        "declared_level": declared,
        "declared_name": LEVEL_NAMES[declared],
        "attack": attack,
        "operational_facts": facts,
        "measurement": measurement,
        "measured_level": measured,
        "measured_name": LEVEL_NAMES[measured],
        "matches_declared": measured == declared,
        # The same facts read against the governing method document's ladder.
        # Kept in its own block, and named differently, so no reader can take a
        # level from one scale for a level of the other.
        "plan_level": {
            "ladder": "NOVELTY_PROOF_PLAN.md §5.2 (five levels)",
            "level": plan_measured,
            "name": PLAN_LEVEL_NAMES[plan_measured],
            "primary_derivation": PLAN_LEVEL_NAMES[plan_primary],
            "second_derivation": PLAN_LEVEL_NAMES[plan_second],
            "agrees": plan_agrees,
            "status": "reproduced" if plan_agrees else "unresolved",
            "hypothesis": (
                None
                if hypothesis is None
                else {
                    "plan_says": hypothesis[1],
                    "level": hypothesis[0],
                    "holds": plan_measured == hypothesis[0],
                }
            ),
        },
        "source_trail": {
            "command": command,
            "artefact_sha256": artefact_sha256,
            "scored_by": "detection.classify via scripts/capability_calibration.py::score",
        },
        "reproduction": {
            "status": status,
            "primary_derivation": LEVEL_NAMES[primary],
            "second_derivation": LEVEL_NAMES[second],
            "agrees": agrees,
            "method": (
                "Both derivations map the recorded operational_facts to the ladder in "
                "admissibility.py:68-71, in opposite decision orders, without reference "
                "to the other's conclusion."
            ),
            "independent_human_reviewer": False,
            "note": (
                "§9.15 asks for AS↔NI reproduction. This record was produced in one "
                "session by one author and is labelled as such rather than presented as "
                "a second member's confirmation."
            ),
        },
    }


# --------------------------------------------------------------- strategies


def measure_container(workdir: Path) -> list[dict]:
    """The container exemption, against the two attacks that defeat it."""
    results = []

    # --- Attack 1: the standard-library valid container (§9.3 finding 2)
    payload = deterministic_payload("container:gzip")
    # mtime=0 pins the header timestamp. gzip.compress writes the current time
    # by default, which made this the one artefact_sha256 in the report that a
    # reader could not reproduce (found in P8.4, 5 September 2026). The attack
    # is unchanged - an attacker would call gzip.compress either way, and the
    # stream still inflates, so container_status is still VALID and the level
    # is still negligible / plan Level 1.
    blob = gzip.compress(payload, mtime=0)
    path = workdir / "cap_gzip_stdlib.gz"
    path.write_bytes(blob)
    outcome = score(path)

    results.append(
        record(
            strategy="container_exemption / standard-library valid container",
            kind="avoidance",
            table_key="structural_mismatch",
            declared=admissibility.AVOIDANCE_COST["structural_mismatch"],
            attack={
                "description": "Wrap the ciphertext in a genuine gzip member.",
                "construction": "gzip.compress(ciphertext, mtime=0)",
                "why_it_works": (
                    "containers._validate_gzip inflates a bounded prefix and the stream "
                    "really does inflate, so container_status is VALID and classify "
                    "returns benign_compressed on the exemption at detection.py:702."
                ),
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": True,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 1,
                "requires_secret_or_preimage": False,
                "write_location_only": False,
            },
            measurement={
                "container_status": outcome["container_status"],
                "verdict": outcome["verdict"],
                "suspicious": outcome["suspicious"],
                "entropy": outcome["entropy"],
                "attack_succeeded": not outcome["suspicious"],
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(blob),
        )
    )

    # --- Attack 2: ZIP_STORED, which does not even compress
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("payload.bin", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 0
        archive.writestr(info, deterministic_payload("container:zip"))
    blob = buffer.getvalue()
    path = workdir / "cap_zip_stored.zip"
    path.write_bytes(blob)
    outcome = score(path)

    results.append(
        record(
            strategy="container_exemption / ZIP_STORED valid container",
            kind="avoidance",
            table_key="structural_mismatch",
            declared=admissibility.AVOIDANCE_COST["structural_mismatch"],
            attack={
                "description": "Store the ciphertext verbatim in a genuine ZIP member.",
                "construction": "ZipFile(..., ZIP_STORED).writestr(name, ciphertext)",
                "why_it_works": (
                    "A real local header, a real central directory and a real EOCD. "
                    "ZIP_STORED means the payload is carried byte for byte, so the "
                    "attacker gives up nothing to get the exemption."
                ),
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": True,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 2,
                "requires_secret_or_preimage": False,
                "write_location_only": False,
            },
            measurement={
                "container_status": outcome["container_status"],
                "verdict": outcome["verdict"],
                "suspicious": outcome["suspicious"],
                "entropy": outcome["entropy"],
                "attack_succeeded": not outcome["suspicious"],
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(blob),
        )
    )

    return results


def measure_entropy_strategies(workdir: Path) -> list[dict]:
    """static_entropy and entropy_rise."""
    results = []

    # --- static_entropy: four bytes, on any of the 11 unvalidated formats
    blob = b"Rar!\x1a\x07" + deterministic_payload("static:rar")
    path = workdir / "cap_static_rar.rar"
    path.write_bytes(blob)
    unvalidated = score(path)

    forged = b"PK\x03\x04" + deterministic_payload("static:zip")
    forged_path = workdir / "cap_static_zip.zip"
    forged_path.write_bytes(forged)
    validated = score(forged_path)

    results.append(
        record(
            strategy="static_entropy / magic bytes over ciphertext",
            kind="avoidance",
            table_key="static_entropy",
            declared=admissibility.AVOIDANCE_COST["static_entropy"],
            attack={
                "description": "Write a recognised container magic over the payload.",
                "construction": 'b"Rar!\\x1a\\x07" + ciphertext',
                "why_it_works": (
                    "rar is one of the 11 formats with no validator, so "
                    "validate_container returns None and the exemption at "
                    "detection.py:702 admits it. Against a validated format the same "
                    "attack now fails - the zip control below returns "
                    f"{validated['verdict']} on the {validated['signal']} signal."
                ),
                "validated_format_control": {
                    "construction": 'b"PK\\x03\\x04" + ciphertext',
                    "container_status": validated["container_status"],
                    "verdict": validated["verdict"],
                    "signal": validated["signal"],
                    "suspicious": validated["suspicious"],
                },
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": False,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 1,
                "requires_secret_or_preimage": False,
                "write_location_only": False,
            },
            measurement={
                "container_status": unvalidated["container_status"],
                "verdict": unvalidated["verdict"],
                "suspicious": unvalidated["suspicious"],
                "entropy": unvalidated["entropy"],
                "attack_succeeded": not unvalidated["suspicious"],
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(blob),
        )
    )

    # --- entropy_rise: write where nothing has been measured
    payload = deterministic_payload("rise")
    fresh_path = workdir / "cap_rise_fresh.docx"
    fresh_path.write_bytes(payload)
    fresh = score(fresh_path)
    observed = score(fresh_path, entropy_delta=3.35)

    results.append(
        record(
            strategy="entropy_rise / write to an unobserved path",
            kind="avoidance",
            table_key="entropy_rise",
            declared=admissibility.AVOIDANCE_COST["entropy_rise"],
            attack={
                "description": (
                    "Do not overwrite a file the Monitor has measured. Write the "
                    "ciphertext to a path with no history - or delete the original "
                    "first, which clears the history at app.py:349 - and the "
                    "differential signal has nothing to rise from."
                ),
                "construction": "open(new_path, 'wb').write(ciphertext)",
                "why_it_works": (
                    "EntropyHistory.observe returns None on a first sighting "
                    "(detection.py:563), so entropy_delta is None and the rise branch "
                    "at detection.py:661 is unreachable."
                ),
                "observed_path_control": {
                    "entropy_delta": 3.35,
                    "verdict": observed["verdict"],
                    "signal": observed["signal"],
                    "suspicious": observed["suspicious"],
                },
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": False,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 1,
                "requires_secret_or_preimage": False,
                # The entire attack is a choice of where to write.
                "write_location_only": True,
            },
            measurement={
                "fresh_path_verdict": fresh["verdict"],
                "fresh_path_signal": fresh["signal"],
                "fresh_path_suspicious": fresh["suspicious"],
                "observed_path_verdict": observed["verdict"],
                "observed_path_signal": observed["signal"],
                "attack_succeeded": (
                    not fresh["suspicious"] or fresh["signal"] != "entropy_rise"
                ),
                "note": (
                    "The fresh write is still caught, by static_entropy rather than "
                    "entropy_rise - it has no container header. What the attack buys "
                    "is the removal of the one signal a valid container cannot cancel, "
                    "which is why it is measured here and not in isolation."
                ),
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(payload),
        )
    )

    # --- partial_entropy: keep every block under the block threshold.
    #
    # P5.4 recorded this as not buildable without the attacker writing
    # format-aware, distribution-aware code, and derived MODERATE from that.
    # **That reasoning was wrong**, and NOVELTY_PROOF_PLAN.md §5.3 says why in one
    # word: base64. §5.1 asks for a search of the standard library for the
    # cheapest strategy that defeats each signal, and the search was not done for
    # this row. `base64.b64encode` is one statement, ships nothing, knows nothing
    # about any format, and flattens ciphertext from 8.00 bits/byte to exactly
    # 6.00 - under the block threshold, under the file threshold, and under the
    # differential floor. The attacker does not encrypt less; they encrypt
    # everything and pay 33% in file size.
    #
    # The old record and its reasoning are preserved in the report under
    # `superseded`, because a level that moved should show what moved it.
    variants = {}
    for label, encoded in (
        ("base64", base64.b64encode(deterministic_payload("partial:b64"))),
        ("base32", base64.b32encode(deterministic_payload("partial:b32"))),
        ("ascii85", base64.a85encode(deterministic_payload("partial:a85"))),
    ):
        variant_path = workdir / f"cap_partial_{label}.docx"
        variant_path.write_bytes(encoded)
        variants[label] = score(variant_path)

    # The differential control: the same evasion on a path already measured at
    # prose entropy, which is the one signal a flattened payload might still trip.
    prose = (b"quarterly deployment report, section body text. " * 3000)[:PAYLOAD_BYTES]
    watched = workdir / "cap_partial_watched.docx"
    watched.write_bytes(prose)
    history = detection.EntropyHistory()
    first = score(watched)
    history.observe(str(watched), first["entropy"], len(prose))
    flattened = base64.b64encode(deterministic_payload("partial:rise"))
    watched.write_bytes(flattened)
    risen_head, _ = detection.sample_file(str(watched), len(flattened))
    risen_entropy, _ = detection.measure(risen_head)
    risen = score(
        watched,
        entropy_delta=history.observe(str(watched), risen_entropy, len(flattened)),
    )

    b64 = variants["base64"]
    results.append(
        record(
            strategy="partial_entropy / never reach ciphertext entropy in any block",
            kind="avoidance",
            table_key="partial_entropy",
            declared=admissibility.AVOIDANCE_COST["partial_entropy"],
            attack={
                "description": (
                    "Encode the ciphertext so no block reaches the block threshold. "
                    "The alphabet does the flattening; nothing about the encryption "
                    "changes."
                ),
                "construction": "base64.b64encode(ciphertext)",
                "why_it_works": (
                    "Base64 spends 8 output bits per 6 bits of input, so uniform "
                    f"ciphertext lands at exactly {b64['entropy']} bits/byte. That is "
                    f"under HIGH_ENTROPY_BLOCK ({detection.HIGH_ENTROPY_BLOCK}), so no "
                    "block counts as high-entropy and partial_entropy cannot fire; "
                    f"under the file threshold ({detection.DEFAULT_ENTROPY_THRESHOLD}), "
                    "so static_entropy cannot fire; and under ENTROPY_RISE_FLOOR "
                    f"({detection.ENTROPY_RISE_FLOOR}), so entropy_rise cannot fire "
                    "either. One standard-library call defeats all three entropy "
                    "signals at once."
                ),
                "variants": {
                    label: {
                        "entropy": v["entropy"],
                        "verdict": v["verdict"],
                        "signal": v["signal"],
                        "suspicious": v["suspicious"],
                    }
                    for label, v in variants.items()
                },
                "differential_control": {
                    "construction": "prose first, then base64(ciphertext) on the same path",
                    "first_entropy": first["entropy"],
                    "second_entropy": risen["entropy"],
                    "verdict": risen["verdict"],
                    "signal": risen["signal"],
                    "note": (
                        "Two independent reasons the rise does not fire: the delta is "
                        f"under ENTROPY_RISE_THRESHOLD ({detection.ENTROPY_RISE_THRESHOLD}) "
                        "and the result is under the floor."
                    ),
                },
                "superseded": {
                    "previous_construction": (
                        "not built: the attack is a constraint on the encryptor's "
                        "output distribution, not a wrapper around it"
                    ),
                    "previous_level": "moderate",
                    "why_it_was_wrong": (
                        "It assumed flattening the distribution required the attacker "
                        "to encrypt less or to post-process with distribution-aware "
                        "code. An expanding alphabet does it with one call and no "
                        "knowledge of anything. §5.1's locked tooling search was not "
                        "run for this row, and §5.3 names base64 as Level 1 outright."
                    ),
                },
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": True,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 1,
                "requires_secret_or_preimage": False,
                "write_location_only": False,
            },
            measurement={
                "attack_built": True,
                "entropy": b64["entropy"],
                "container_status": b64["container_status"],
                "verdict": b64["verdict"],
                "suspicious": b64["suspicious"],
                "attack_succeeded": not b64["suspicious"],
                "size_cost_ratio": 4 / 3,
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(
                base64.b64encode(deterministic_payload("partial:b64"))
            ),
        )
    )

    # --- ransom_extension: do not rename
    blob = deterministic_payload("ext")
    plain = workdir / "cap_ext_plain.docx"
    plain.write_bytes(blob)
    renamed = workdir / "cap_ext_renamed.docx.locked"
    renamed.write_bytes(blob)
    without = score(plain)
    with_extension = score(renamed)

    results.append(
        record(
            strategy="ransom_extension / do not rename the file",
            kind="avoidance",
            table_key="ransom_extension",
            declared=admissibility.AVOIDANCE_COST["ransom_extension"],
            attack={
                "description": "Leave the original extension in place.",
                "construction": "do nothing",
                "why_it_works": "The signal reads the filename and nothing else.",
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": False,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 0,
                "requires_secret_or_preimage": False,
                "write_location_only": False,
            },
            measurement={
                "with_extension_signal": with_extension["signal"],
                "without_extension_signal": without["signal"],
                "attack_succeeded": without["signal"] != "ransom_extension",
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(blob),
        )
    )

    return results


def measure_whitelist(workdir: Path) -> list[dict]:
    """The two whitelist rules, forgery side."""
    results = []
    payload = deterministic_payload("whitelist")

    # --- path rule: write into an approved directory
    approved = workdir / "approved"
    approved.mkdir(exist_ok=True)
    target = approved / "payload.docx"
    target.write_bytes(payload)

    whitelist = suppression_module.Whitelist(paths=[str(approved / "*")], hashes=[])
    verdict = score(target)
    matched = whitelist.match(str(target), sha256_bytes(payload), verdict)
    decision = admissibility.adjudicate(verdict, matched)

    results.append(
        record(
            strategy="whitelist path rule / write into an approved directory",
            kind="forgery",
            table_key="path",
            declared=admissibility.FORGERY_COST["path"],
            attack={
                "description": "Drop the payload into a directory the operator approved.",
                "construction": "open(approved_dir / name, 'wb').write(ciphertext)",
                "why_it_works": (
                    "Whitelist.match fnmatches the path (suppression.py:166) and "
                    "returns a rule with no reference to the content."
                ),
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": False,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 1,
                "requires_secret_or_preimage": False,
                "write_location_only": True,
            },
            measurement={
                "rule_matched": matched,
                "adjudication_outcome": (decision or {}).get("outcome"),
                "admitted": (decision or {}).get("admitted"),
                "forgery_cost": (decision or {}).get("forgery_cost"),
                "avoidance_cost": (decision or {}).get("avoidance_cost"),
                "attack_succeeded": bool(decision and decision["admitted"]),
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(payload),
        )
    )

    # --- hash rule: a preimage, which is not available
    hash_whitelist = suppression_module.Whitelist(paths=[], hashes=[sha256_bytes(b"an approved file")])
    attempted = hash_whitelist.match(str(target), sha256_bytes(payload), verdict)

    results.append(
        record(
            strategy="whitelist hash rule / produce a file with an approved SHA-256",
            kind="forgery",
            table_key="hash",
            declared=admissibility.FORGERY_COST["hash"],
            attack={
                "description": (
                    "Make the ciphertext hash to a value already in the operator's "
                    "approved set."
                ),
                "construction": "not available: this is a SHA-256 preimage",
                "why_it_is_not_run_here": (
                    "A second-preimage attack on SHA-256 has no known method better "
                    "than brute force at 2^256. The attempt below is the negative "
                    "control - an attacker-controlled file is offered against a "
                    "populated hash whitelist and does not match."
                ),
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": False,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": None,
                "requires_secret_or_preimage": True,
                "write_location_only": False,
            },
            measurement={
                "negative_control_matched": attempted,
                "attack_succeeded": attempted is not None,
                "basis": "SHA-256 second preimage; infeasible, not merely expensive",
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=None,
        )
    )

    return results


def measure_training_mode(workdir: Path) -> list[dict]:
    """The learned ceiling, forgery side - poisoned by writing during training."""
    watched = workdir / "watched"
    watched.mkdir(exist_ok=True)

    # A dwell of zero would not model the deployed mechanism; the shipped
    # requirement is what decides whether the attacker's writes count.
    training = suppression_module.TrainingMode(dwell_seconds=0.0)
    training.start(duration_seconds=60.0)

    # The attacker writes files the training window will learn from. They are
    # high entropy and structurally honest - a real ZIP - because the mechanism
    # keys its ceiling by structural class.
    poison_hashes = []
    for index in range(6):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("payload.bin", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            archive.writestr(info, deterministic_payload(f"training:{index}"))
        data = blob.getvalue()
        path = watched / f"poison_{index}.zip"
        path.write_bytes(data)
        poison_hashes.append(sha256_bytes(data))
        verdict = score(path)
        training.observe(str(path), verdict["entropy"], verdict)

    time.sleep(0.05)  # clear the dwell requirement
    finished = training.finish()

    # Now the attack: a file in the same directory, same extension, same
    # structural class, at or below the ceiling the attacker's own writes set.
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("payload.bin", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 0
        archive.writestr(info, deterministic_payload("training:attack"))
    data = blob.getvalue()
    attack_path = watched / "attack.zip"
    attack_path.write_bytes(data)

    verdict = score(attack_path)
    matched = training.match(str(attack_path), verdict["entropy"], verdict)
    decision = admissibility.adjudicate(verdict, matched)

    return [
        record(
            strategy="training_mode / poison the learned ceiling during the window",
            kind="forgery",
            table_key="training_mode",
            declared=admissibility.FORGERY_COST["training_mode"],
            attack={
                "description": (
                    "Write high-entropy files into the watched tree while the operator's "
                    "training window is open, so the learned ceiling for that "
                    "extension and structural class is set by the attacker's own files."
                ),
                "construction": "write 6 files during training, then write the payload",
                "why_it_works": (
                    "TrainingMode learns from writes (suppression.py:365) and the "
                    "attacker can write. The dwell and structural-class requirements "
                    "raise the price but do not change who supplies the samples."
                ),
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": False,
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 6,
                "requires_secret_or_preimage": False,
                "write_location_only": True,
            },
            measurement={
                "training_state_after_finish": finished,
                "poison_files": len(poison_hashes),
                "attack_verdict": verdict["verdict"],
                "attack_signal": verdict["signal"],
                "rule_matched": matched,
                "adjudication_outcome": (decision or {}).get("outcome"),
                "admitted": (decision or {}).get("admitted"),
                "forgery_cost": (decision or {}).get("forgery_cost"),
                "avoidance_cost": (decision or {}).get("avoidance_cost"),
                "attack_succeeded": bool(decision and decision["admitted"]),
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(data),
        )
    ]


# ------------------------------------------- NI: Cforge(ml_confidence_gate)


def build_intermittent_in_valid_container(workdir: Path) -> dict:
    """A real ZIP whose member is part ciphertext, part plaintext.

    The composite the feature search points at, built as an actual file and put
    through the actual detection path, so the claim is measured rather than
    reasoned from two branch conditions.

    The member alternates 4KB blocks - ciphertext, then prose - which is what
    intermittent encryption produces and what the block statistics in
    `detection.measure` are there to catch.
    """
    block = 4096
    blocks = 40
    parts = []
    for index in range(blocks):
        if index % 2 == 0:
            parts.append(hashlib.shake_256(f"intermittent:{index}".encode()).digest(block))
        else:
            filler = (f"section {index} of the quarterly deployment report. ").encode()
            parts.append((filler * (block // len(filler) + 1))[:block])
    member = b"".join(parts)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("annual_report.docx", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 0
        archive.writestr(info, member)
    blob = buffer.getvalue()

    path = workdir / "cap_intermittent_in_zip.zip"
    path.write_bytes(blob)

    size = path.stat().st_size
    head, tail = detection.sample_file(str(path), size)
    entropy, statistics = detection.measure(head)
    magic = detection.read_magic(str(path))
    container = detection.identify_container(magic)
    tri_state = containers.validate_container(head, tail, container, size)
    verdict = detection.classify(
        str(path),
        entropy,
        magic,
        detection.DEFAULT_ENTROPY_THRESHOLD,
        readable=True,
        entropy_delta=None,
        container_valid=tri_state,
        statistics=statistics,
    )

    return {
        "construction": (
            f"ZIP_STORED member of {blocks} alternating 4KB blocks, "
            "ciphertext and prose"
        ),
        "encrypted_block_fraction_by_construction": 0.5,
        "sha256": sha256_bytes(blob),
        "size": size,
        "whole_file_entropy": entropy,
        "container_status": containers.container_status(head, tail, container, size),
        "validate_container": tri_state,
        "high_entropy_block_fraction": statistics.get("high_entropy_block_fraction"),
        "entropy_block_spread": statistics.get("entropy_block_spread"),
        "verdict": verdict["verdict"],
        "suspicious": verdict["suspicious"],
        "signal": verdict["signal"],
        "reason": verdict["reason"],
        "reached_the_ml_engine": verdict["suspicious"],
    }


def measure_ml_confidence_gate(workdir: Path) -> list[dict]:
    """NI's strategy: hold the model under 0.7 while still encrypting the file.

    §9.3 finding 3 says the confidence gate withholds a response silently. Two
    separate questions fall out of that, and this measures both:

      1. Can an attacker hold the behavioural model's ransomware confidence
         below 0.7 while the file is still ciphertext? That is a search over the
         feature vector, run against the deployed model.
      2. If they can, does anything downstream actually withhold? That is a
         property of pipeline.effective_threat_level, and it is checked here
         rather than assumed.
    """
    model_path = REPO_ROOT / "models" / "behavioral_model.pkl"
    if not model_path.exists():
        return [
            {
                "strategy": "Cforge(ml_confidence_gate)",
                "kind": "avoidance",
                "measured_level": None,
                "measured_name": None,
                "reproduction": {"status": "unresolved", "agrees": False,
                                 "independent_human_reviewer": False},
                "measurement": {
                    "attack_succeeded": None,
                    "basis": f"no model at {model_path}; nothing to measure against",
                },
            }
        ]

    sys.path.insert(0, str(REPO_ROOT / "services" / "ml-engine"))
    from features import FEATURE_ORDER, features_to_vector  # noqa: E402

    import numpy as np

    with model_path.open("rb") as handle:
        model = pickle.load(handle)

    def confidence_for(feature_dict: dict) -> tuple[str, float]:
        vector = np.asarray([features_to_vector(feature_dict)], dtype=np.float32)
        proba = model.predict_proba(vector)[0]
        index = int(np.argmax(proba))
        return ("ransomware" if index == 1 else "benign"), float(proba[index])

    # The attacker's objective is unchanged: the file's content is ciphertext.
    # What they vary is everything the model reads *around* that - the declared
    # container, whether it validates, the block statistics. Each row is a
    # feature vector a real file could produce, and the search is over which of
    # them the model scores under 0.7.
    base = {
        "shannon_entropy": 7.997,
        "file_size": 120_000,
        "has_container_header": 0,
        "container_structurally_valid": 0,
        "ransom_extension": 1,
        "printable_ratio": 0.38,
        "byte_value_std": 73.9,
        "chi_square_uniformity": 0.98,
        "entropy_max_block": 7.999,
        "entropy_block_spread": 0.004,
        "high_entropy_block_fraction": 1.0,
    }

    trials = []
    variations = [
        ("naked ciphertext, ransom extension", {}),
        ("drop the ransom extension", {"ransom_extension": 0}),
        ("declare a container header", {"ransom_extension": 0, "has_container_header": 1}),
        (
            "declare a structurally valid container",
            {"ransom_extension": 0, "has_container_header": 1, "container_structurally_valid": 1},
        ),
        (
            "valid container, softened block statistics",
            {
                "ransom_extension": 0,
                "has_container_header": 1,
                "container_structurally_valid": 1,
                "high_entropy_block_fraction": 0.55,
                "entropy_block_spread": 1.9,
                "shannon_entropy": 7.62,
            },
        ),
        (
            "valid container, entropy at the detector threshold",
            {
                "ransom_extension": 0,
                "has_container_header": 1,
                "container_structurally_valid": 1,
                "shannon_entropy": 7.5,
                "entropy_max_block": 7.72,
                "high_entropy_block_fraction": 0.42,
                "entropy_block_spread": 2.4,
                "printable_ratio": 0.44,
            },
        ),
    ]

    for label, override in variations:
        candidate = {**base, **override}
        prediction, confidence = confidence_for(candidate)
        ransomware_confidence = confidence if prediction == "ransomware" else 1.0 - confidence

        # "Still meeting the attacker objective" needs a definition that is not
        # just "entropy is high". The objective is that the victim cannot read
        # their file back. Intermittent encryption meets it while leaving a
        # substantial fraction of blocks untouched - that is what intermittent
        # encryption *is*, and families use it to go faster, not to be gentler.
        # So the objective test is the encrypted fraction, and the entropy is
        # recorded next to it rather than standing in for it.
        encrypted_fraction = candidate["high_entropy_block_fraction"]
        trials.append(
            {
                "variation": label,
                "overrides": override,
                "prediction": prediction,
                "confidence": round(confidence, 4),
                "ransomware_confidence": round(ransomware_confidence, 4),
                "under_0_7_gate": ransomware_confidence < 0.7,
                "whole_file_entropy": candidate["shannon_entropy"],
                "encrypted_block_fraction": encrypted_fraction,
                # Conti and BlackCat ship at well under half the file; 0.4 is a
                # conservative floor for "the victim has lost the file".
                "attacker_objective_met": encrypted_fraction >= 0.4,
            }
        )

    succeeded = [t for t in trials if t["under_0_7_gate"] and t["attacker_objective_met"]]

    # Question 2: does anything downstream withhold, given the only caller?
    sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))
    import pipeline as monitor_pipeline  # noqa: E402

    composite = build_intermittent_in_valid_container(workdir)

    withheld_check = {
        "effective_threat_level('low', suspicious=True)": monitor_pipeline.effective_threat_level("low", True),
        "effective_threat_level('medium', suspicious=True)": monitor_pipeline.effective_threat_level("medium", True),
        "effective_threat_level('low', suspicious=False)": monitor_pipeline.effective_threat_level("low", False),
        "actionable_levels": sorted(monitor_pipeline.ACTIONABLE_THREAT_LEVELS),
    }
    floored_is_actionable = (
        monitor_pipeline.effective_threat_level("low", True)
        in monitor_pipeline.ACTIONABLE_THREAT_LEVELS
    )

    return [
        record(
            strategy="Cforge(ml_confidence_gate) / hold ransomware confidence under 0.7",
            kind="avoidance",
            table_key="(not in the cost table - the ML gate is ungoverned)",
            declared=admissibility.UNKNOWN_AVOIDANCE,
            attack={
                "description": (
                    "Keep the behavioural model's ransomware confidence below the 0.7 "
                    "threshold in ml-engine/app.py:157 while the file is still "
                    "ciphertext, so the threat level lands at medium or low."
                ),
                "construction": (
                    "vary the declared container, its validity and the block statistics "
                    "around unchanged high-entropy content"
                ),
                "trials": trials,
            },
            facts={
                "third_party_dependencies": [],
                "public_primitive": True,
                # The successful variations require producing a structurally valid
                # container, which is the same work the container attack needs.
                "ships_an_encoder": False,
                "format_specific_knowledge": False,
                "attacker_statements": 2,
                "requires_secret_or_preimage": False,
                "write_location_only": False,
            },
            measurement={
                "variations_tried": len(trials),
                "variations_under_the_gate_while_still_ciphertext": len(succeeded),
                "successful_variations": [t["variation"] for t in succeeded],
                "attack_succeeded": bool(succeeded),
                "downstream_withholding": withheld_check,
                "monitor_floor_makes_gate_unreachable": floored_is_actionable,
                "empirical_composite_witness": composite,
                "finding_3_status": (
                    "restated" if floored_is_actionable else "confirmed"
                ),
                "finding_3_note": (
                    "§9.3 finding 3 says a sub-threshold confidence silently withholds "
                    "the response. pipeline.effective_threat_level floors a "
                    "Monitor-suspicious event at 'high', and pipeline.run is only "
                    "reached for suspicious events (app.py:491), so on the only live "
                    "caller the gate cannot withhold. What the confidence gate does "
                    "still cost is the *distinction*: a case the model scored 0.2 and "
                    "a case it scored 0.95 both reach the ledger as threat_level high, "
                    "with model_threat_level recorded alongside. The silent suppression "
                    "§9.3 describes is upstream - it is the container exemption at "
                    "detection.py:702, which stops the event reaching the model at all."
                ),
                "composite_finding": (
                    "The two variations that get under the gate do it by declaring a "
                    "structurally valid container and encrypting part of the file "
                    "rather than all of it. empirical_composite_witness builds that as "
                    "a real file and puts it through the real detection path, and the "
                    "measurement corrects the mechanism this note first reasoned to. "
                    "A ZIP_STORED archive whose member is 40 alternating 4KB blocks of "
                    "ciphertext and prose measures at 6.84 bits/byte whole-file - below "
                    "the 7.5 threshold - with high_entropy_block_fraction 0.5 and "
                    "block spread 3.87. The partial_entropy branch at detection.py:690 "
                    "exists for exactly this profile, and it is not reached: its guard "
                    "is `container_valid is not True`, and the container is genuinely "
                    "valid. classify() falls through to the final line and returns "
                    "plain `benign` - not even benign_compressed - so the event is "
                    "never fanned out (app.py:491) and the model never scores it. "
                    "Half the file is unrecoverable and the system's verdict is "
                    "'entropy 6.84 below threshold 7.5'. The confidence gate is not "
                    "what suppressed this; the container exemption's reach into the "
                    "partial-entropy guard is."
                ),
            },
            command=".venv/Scripts/python.exe scripts/capability_calibration.py",
            artefact_sha256=sha256_bytes(model_path.read_bytes()),
        )
    ]


# ------------------------------------------------------------------- report


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="capability_") as tmp:
        workdir = Path(tmp)
        levels = (
            measure_container(workdir)
            + measure_entropy_strategies(workdir)
            + measure_whitelist(workdir)
            + measure_training_mode(workdir)
            + measure_ml_confidence_gate(workdir)
        )

    reproduced = [r for r in levels if r.get("reproduction", {}).get("status") == "reproduced"]
    unresolved = [r for r in levels if r.get("reproduction", {}).get("status") == "unresolved"]
    disagreements = [r for r in levels if r.get("matches_declared") is False]

    # Table 9.8 asks for "capability levels with a reproducible source trail -
    # 100%". A record whose attack was never built has a rationale, not a trail,
    # and counting the two together would report 100% for a set that includes
    # one level nobody can re-run. They are counted apart.
    # "Empirical" means an attack was actually executed and its outcome
    # recorded - succeeding or failing. An artefact hash is not the test: the
    # SHA-256 preimage attack legitimately has no artefact, and its negative
    # control (an attacker-controlled file offered against a populated hash
    # whitelist, which did not match) is a real measurement. Only a level whose
    # attack was never built is derived-only.
    empirical = [
        r for r in levels if r.get("measurement", {}).get("attack_succeeded") is not None
    ]
    derived_only = [r for r in levels if r not in empirical]

    report = {
        "schema": "urds.capability_calibration/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "ladder": {
            str(value): name for value, name in sorted(LEVEL_NAMES.items())
        },
        "ladder_source": "services/monitor/admissibility.py:68-71",
        "plan_ladder": {
            str(value): name for value, name in sorted(PLAN_LEVEL_NAMES.items())
        },
        "plan_ladder_source": "NOVELTY_PROOF_PLAN.md §5.2",
        "two_ladders_note": (
            "Every strategy carries a level on both scales, derived twice each "
            "from the same recorded operational facts. They are not comparable "
            "rung for rung: the code's LOW ('a location the attacker can already "
            "write to') has no counterpart in the plan, which puts choosing a "
            "path in Level 0 alongside choosing bytes, and the code's HIGH "
            "conflates the plan's Level 3 and Level 4."
        ),
        "second_reviewer_statement": (
            "§9.15 requires the AS↔NI ring. Every level here was derived twice, in "
            "opposite decision orders, over the same recorded operational facts and "
            "without reference to the first conclusion - which is the reproduction "
            "protocol. Both derivations were written in one session by one author. No "
            "record claims an independent human reviewer, and every record carries "
            "reproduction.independent_human_reviewer = false."
        ),
        "summary": {
            "levels_measured": len(levels),
            "with_empirical_source_trail": len(empirical),
            "derived_from_source_only": [
                {
                    "strategy": r["strategy"],
                    "why": r["attack"].get("why_it_is_not_run_here", "attack not built"),
                }
                for r in derived_only
            ],
            "reproduced": len(reproduced),
            "unresolved_under_d2": len(unresolved),
            "disagree_with_the_declared_cost_table": [
                {
                    "strategy": r["strategy"],
                    "declared": r["declared_name"],
                    "measured": r["measured_name"],
                }
                for r in disagreements
            ],
        },
        "levels": levels,
    }

    print(f"levels measured: {len(levels)}   empirical trail: {len(empirical)}   "
          f"derived only: {len(derived_only)}   reproduced: {len(reproduced)}   "
          f"unresolved: {len(unresolved)}")
    print(f"{'strategy':<62} {'declared':<11} {'measured':<11} attack")
    for row in levels:
        if row.get("measured_name") is None:
            continue
        succeeded = row["measurement"].get("attack_succeeded")
        mark = {True: "succeeded", False: "failed", None: "not run"}[succeeded]
        flag = "" if row["matches_declared"] else "   <-- differs"
        print(f"{row['strategy'][:60]:<62} {row['declared_name']:<11} "
              f"{row['measured_name']:<11} {mark}{flag}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "capability_calibration.json").write_text(json.dumps(report, indent=2))
    print(f"\nwrote {REPORTS / 'capability_calibration.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
