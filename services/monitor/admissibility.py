"""When a suppression is allowed to cancel a detection - AS.

Table 5.7 asks for false-positive suppression, and services/monitor/suppression.py
builds it: a whitelist and a training mode. Both are holes in the detector by
construction, and the module docstring there states the rule that keeps them
honest - *a suppression may never survive evidence that the file was replaced*.
That rule was arrived at twice, by hand, for two specific cases: a content hash
holds where a path rule gives way, and a learned entropy ceiling yields to a
differential-entropy rise.

Both hand-derived rules are instances of one principle, and stating the
principle is what makes the other cases fall out instead of having to be noticed:

    Every detection signal has an **avoidance cost** - what an attacker must
    spend to not trigger it. Every suppression has a **forgery cost** - what an
    attacker must spend to make it fire on a file they control.

    A suppression may cancel a detection only when forging the suppression
    costs **strictly more** than avoiding the detection.

Where it does not, the suppression is not discarded - it is *attenuated*: the
alert stands, and both costs are recorded on the event and into the ledger, so
an operator can see that a rule they wrote was consulted, was outranked, and by
how much. A suppression that vanishes without saying so is indistinguishable
from a detector that never fired.

Why this ordering and not a severity ordering
---------------------------------------------
Severity says how bad the outcome is. Cost says how easy the mechanism is to
turn around and use. Those come apart, and it is the second that decides whether
a suppression is safe:

  * A known ransomware extension is the *loudest* signal here and the cheapest
    to avoid - the attacker simply does not rename the file. It ranks lowest.
  * A SHA-256 whitelist entry is the most permissive suppression in the system
    and the most expensive to forge - it needs a preimage. It ranks highest, and
    it is right that it outranks everything, because a file whose bytes hash to
    an approved value *is* the approved file.
  * The static entropy threshold was, until structural validation existed,
    avoidable for four bytes. That is why NEGLIGIBLE and not LOW: writing
    "PK\\x03\\x04" over a payload is free, and the exemption it bought was
    therefore worth exactly nothing against an attacker who read the source.

Read against the table below, the two rules found by hand are the two rows they
have to be, and the two that were missed - a training-mode ceiling cancelling a
structural mismatch, and a training-mode ceiling cancelling intermittent
encryption - are refused without anyone having to think of them first.

This module decides admissibility only. Two further defects are not about
cancellation but about the *formation* of the evidence - a ceiling raised by
files the attacker created, and an entropy floor flushed by writes the attacker
chose - and those are fixed where they are formed, in suppression.TrainingMode
and detection.EntropyHistory respectively.
"""

from __future__ import annotations

# An ordinal scale, not a currency. The numbers only ever get compared to each
# other, and the gaps between them carry no meaning - what matters is which
# kinds of work an attacker has to do, in order.
NEGLIGIBLE = 0  # bytes the attacker chooses freely: a filename, a magic number
LOW = 1  # a location the attacker can already write to
MODERATE = 2  # well-formed output the attacker must actually produce
HIGH = 3  # a secret or a preimage the attacker cannot produce at all

COST_NAMES = {NEGLIGIBLE: "negligible", LOW: "low", MODERATE: "moderate", HIGH: "high"}


# What it costs an attacker to *avoid* each detection signal, keyed by the
# `signal` field detection.classify puts on every verdict.
AVOIDANCE_COST: dict[str, int] = {
    # Do not append ".locked". Costs nothing at all.
    "ransom_extension": NEGLIGIBLE,
    # Write any recognised container magic over the payload - four bytes, and
    # the exemption in classify() used to be worth exactly that.
    "static_entropy": NEGLIGIBLE,
    # Emit a file that is genuinely the format it declares: real ZIP framing,
    # a correct PNG CRC, a JPEG marker chain. An encryptor that does this has to
    # ship an encoder and leave real structure in the output.
    "structural_mismatch": MODERATE,
    # Never let any 4KB block reach ciphertext entropy - which rules out using a
    # stream cipher on any region of the file. Intermittent encryption exists to
    # go *faster*; this takes that back.
    "partial_entropy": MODERATE,
    # Ensure the path was never observed at lower entropy. Either write to a
    # path the monitor has never seen - which gives up the original filename -
    # or flush the floor, which detection.EntropyHistory no longer permits.
    "entropy_rise": MODERATE,
}

# What it costs an attacker to make each suppression fire on a file they control,
# keyed by the `rule` field suppression.Whitelist / TrainingMode return.
FORGERY_COST: dict[str, int] = {
    # Produce a file whose SHA-256 already appears in the operator's approved
    # set. That is a preimage, and it is not available.
    "hash": HIGH,
    # Write into a directory the operator approved. An attacker who is running
    # on the machine at all can usually do this.
    "path": LOW,
    # Get a file counted into the learned baseline for an extension. Cheap by
    # construction - the baseline is learned from writes, and the attacker can
    # write. suppression.TrainingMode raises the price with a dwell requirement
    # and a structural-class requirement, but not to the point where it should
    # be allowed to cancel evidence that costs MODERATE to avoid.
    "training_mode": LOW,
}

# An unrecognised signal is treated as the most expensive thing to avoid, and an
# unrecognised suppression as the cheapest thing to forge. Both defaults fail
# closed: a new detection added without a cost entry keeps its alert, and a new
# suppression added without one suppresses nothing until someone prices it.
UNKNOWN_AVOIDANCE = HIGH
UNKNOWN_FORGERY = NEGLIGIBLE


def avoidance_cost(signal: str | None) -> int:
    if signal is None:
        return NEGLIGIBLE
    return AVOIDANCE_COST.get(signal, UNKNOWN_AVOIDANCE)


def forgery_cost(rule: str | None) -> int:
    if rule is None:
        return UNKNOWN_FORGERY
    return FORGERY_COST.get(rule, UNKNOWN_FORGERY)


def adjudicate(verdict: dict, suppression: dict | None) -> dict | None:
    """Decide what a matched suppression is allowed to do to this verdict.

    Returns None when no suppression was matched. Otherwise returns the record
    that goes on the event and into the ledger:

        {"rule", "value", "admitted", "outcome", "forgery_cost",
         "avoidance_cost", "signal", "reason"}

    `admitted` is the only field the detector acts on - True cancels the alert,
    False leaves it standing. The rest exists so the decision can be audited
    without reading this file.
    """
    if suppression is None:
        return None

    signal = verdict.get("signal")
    forging = forgery_cost(suppression.get("rule"))
    avoiding = avoidance_cost(signal)
    # Strict, per NOVELTY_PROOF_PLAN.md §5.3: "equal capability does not
    # demonstrate that the mitigation is harder to forge". A tie is not
    # evidence, so a tie no longer admits.
    #
    # Against the declared table above this changes nothing: all 15
    # rule × signal cells decide the same way under `>` as under `>=`, which is
    # what `scripts/admission_recompute.py` reports as policy B, and the four
    # cells the strict rule *does* move are moved by the P5.4 measured costs
    # (policy D), which are not deployed here. The one reachable difference the
    # change could make is a rule not in FORGERY_COST meeting a verdict with no
    # signal, and `app.handle_event` only adjudicates suspicious verdicts, which
    # always carry one.
    admitted = forging > avoiding

    return {
        **suppression,
        "admitted": admitted,
        "outcome": "cancelled" if admitted else "attenuated",
        "signal": signal,
        "forgery_cost": COST_NAMES[forging],
        "avoidance_cost": COST_NAMES[avoiding],
        "reason": (
            f"forging the {suppression.get('rule')} rule costs {COST_NAMES[forging]}; "
            f"avoiding the {signal or 'benign'} signal costs {COST_NAMES[avoiding]}"
            + (
                " - the suppression is strictly more expensive, so it applies"
                if admitted
                else " - the suppression is cheaper than the evidence, so the alert stands"
            )
        ),
    }
