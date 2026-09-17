"""What the installer and the uninstaller must not get wrong again.

Two of the three defects these pin were found by running the thing, not by
reading it, and both were silent in the direction that matters - the machine
looked configured and was not:

  * `icacls DIR /inheritance:r /grant:r "SID:(OI)(CI)F" /T` leaves every *file*
    under DIR with an empty DACL. Measured, elevated, on Windows 11 26200: the
    ACL prints blank and an elevated Administrator is denied opening the file.
    It locked the agent out of its own ledger - `sqlite3.OperationalError:
    unable to open database file` - and the service registered, reported
    AUTO_START, and stopped.
  * `setup_attribution_audit.ps1 -Revert` disables the File System audit
    subcategory **machine-wide**. An uninstaller that reverts one protected root
    takes attribution away from every other root on the machine, and from
    anything else using file auditing. The agent that loses it keeps running and
    reports every write as `unknown` for ever.
  * `python -m agent` needs the repository as the working directory. An elevated
    console starts in system32, so the first run of the installer got "No module
    named agent" from every call and reported it as a rejected configuration.

These are assertions about the text of PowerShell scripts, which is a blunt
instrument. They are here because the alternative is a comment, and a comment
does not fail. Each one names the behaviour it is protecting rather than the
string it matches, so a rewrite that keeps the behaviour can move the string and
update the test knowing what it is for.

The PowerShell parse checks are Windows-only and say so. Everything else runs
anywhere, which is where CI runs.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "install.ps1"
UNINSTALL = ROOT / "uninstall.ps1"
AUDIT = ROOT / "scripts" / "setup_attribution_audit.ps1"
STACK = ROOT / "scripts" / "start_stack.ps1"
SELFTEST = ROOT / "scripts" / "selftest.py"
WRITER = ROOT / "scripts" / "selftest_writer.py"

SCRIPTS = (INSTALL, UNINSTALL, AUDIT, STACK)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


# ------------------------------------------------------------------ existence


@pytest.mark.parametrize("path", [*SCRIPTS, SELFTEST, WRITER],
                         ids=lambda p: p.name)
def test_the_installer_ships_every_piece_it_calls(path: Path):
    assert path.is_file(), f"{path} is referenced by the install path and is missing"


def test_the_installer_is_at_the_repository_root():
    """"Right-click -> Run with PowerShell" only works if it is where you look.

    Moving it into scripts/ would be tidier and would break the one instruction
    a person following the README is given.
    """
    assert INSTALL.parent == ROOT
    assert UNINSTALL.parent == ROOT


# ----------------------------------------------------- the machine-wide hazard


def test_uninstall_never_disables_file_auditing_unconditionally():
    """The subcategory is machine-wide; the SACL is not.

    `auditpol ... /success:disable` may appear only inside the branch that has
    established, from the install receipt, that URDS was the thing that enabled
    it. Anywhere else and uninstalling URDS silently disables file auditing for
    whatever else on the machine depends on it.
    """
    text = read(UNINSTALL)
    # Invocations only. The no-receipt branch *prints* this command as advice,
    # and a string telling somebody what they could run is not the script
    # running it.
    disable_calls = [m.start() for m in
                     re.finditer(r"&\s*auditpol[^\n]*success:disable", text)]
    assert disable_calls, "uninstall.ps1 no longer disables the subcategory at all"

    guard = text.find("prior.audit_subcategory_was_enabled")
    assert guard != -1, (
        "uninstall.ps1 does not consult the receipt's record of whether file "
        "auditing was already on before URDS was installed")

    for position in disable_calls:
        assert position > guard, (
            "auditpol /success:disable is called before, or outside, the branch "
            "that checks prior.audit_subcategory_was_enabled. Reverting a "
            "machine-wide setting this installer may not have made is how "
            "attribution disappears from every other protected root.")


def test_uninstall_removes_sacls_without_touching_the_policy():
    """One root at a time, and the machine-wide half left alone until the end."""
    text = read(UNINSTALL)
    assert "-Revert -SaclOnly" in text, (
        "uninstall.ps1 must revert each root's SACL with -SaclOnly. A bare "
        "-Revert disables the subcategory on the first root, so every later "
        "root in the loop is un-audited before its own SACL is removed.")
    bare = re.search(r"-Revert(?!\s+-SaclOnly)", text)
    assert bare is None, (
        f"uninstall.ps1 calls -Revert without -SaclOnly at offset {bare.start() if bare else -1}")


def test_the_audit_script_offers_a_sacl_only_mode():
    text = read(AUDIT)
    assert "$SaclOnly" in text
    assert "[switch]$SaclOnly" in text, (
        "scripts/setup_attribution_audit.ps1 must expose -SaclOnly; uninstall.ps1 "
        "depends on it to revert one root without disabling the machine.")


def test_the_uninstaller_stops_the_agent_before_removing_canaries():
    """A canary is a tripwire. Deleting twenty with the agent running trips it.

    The agent suspends whoever deletes a decoy, immediately and with no
    threshold - that is the whole point of the signal. An uninstaller that
    removes them first gets suspended by the thing it is uninstalling.
    """
    text = read(UNINSTALL)
    stop = text.find("sc.exe stop $ServiceName")
    # The invocation, not a mention of it in a comment.
    remove = text.find("-m agent canary --remove")
    assert stop != -1, "uninstall.ps1 no longer stops the service"
    assert remove != -1, "uninstall.ps1 no longer removes the canaries"
    assert stop < remove, (
        "uninstall.ps1 removes canaries before stopping the agent; the agent "
        "will suspend the process doing the removing")


# ------------------------------------------------------------- the ACL defect


def test_the_installer_does_not_use_the_acl_form_that_empties_file_dacls():
    """`/grant:r "SID:(OI)(CI)F"` with `/T` leaves files with no ACE at all.

    (OI) and (CI) are inheritance flags. Applied with /T straight onto a file
    they carry nothing, and /inheritance:r has already removed what the file
    inherited. Measured: the file's ACL prints blank and an elevated
    Administrator cannot open it.
    """
    text = read(INSTALL)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("&") or "icacls" not in stripped:
            continue
        if "/grant" in stripped and "(OI)(CI)" in stripped:
            assert " /T" not in stripped, (
                f"this leaves every file under the directory with an empty "
                f"DACL, including for SYSTEM:\n  {stripped}")


def test_the_installer_checks_that_the_ledger_still_opens():
    """The directory's ACL is the setting; opening the file is the effect.

    They came apart once: the ACL on the directory read exactly as intended
    while every file beneath it was unopenable by anybody. A check that reads
    the setting back would have passed.
    """
    text = read(INSTALL)
    assert "[System.IO.File]::Open" in text, (
        "install.ps1 must verify the locked-down data directory by opening the "
        "ledger, not only by reading the directory's ACL back")


# --------------------------------------------------------- the working directory


@pytest.mark.parametrize("path", [INSTALL, UNINSTALL], ids=lambda p: p.name)
def test_the_scripts_set_the_working_directory_before_calling_the_agent(path: Path):
    """An elevated console starts in system32.

    `python -m agent` finds the package through the working directory, so
    without this every call returns "No module named agent". install.ps1 did
    that on its first run and reported it as a rejected configuration; the same
    omission in uninstall.ps1 would leave twenty decoys on disk, because the
    only thing that knows which files those are is the manifest that command
    reads.
    """
    text = read(path)
    location = text.find("Set-Location -LiteralPath $RepoRoot")
    # The first one that actually runs, not the first mention in the help.
    first_call = text.find("$venvPython -m agent")
    assert location != -1, (
        f"{path.name} must set its working directory to the checkout")
    if first_call != -1:
        assert location < first_call, (
            f"{path.name} calls `python -m agent` before setting the working "
            f"directory")


# ------------------------------------------------------- the two ledgers rule


def test_the_demonstration_stack_never_opens_the_agents_ledger():
    """Two processes appending to one ledger file fork the chain.

    Measured: 150 appends each from two processes, 300 blocks written,
    verify_chain valid=False at block 116. `add_block` reads the tip and then
    inserts, and Python's sqlite3 does not hold a transaction across the two, so
    the in-process lock that makes it safe for one service does not help across
    processes.

    The dashboard POSTs /predict on every refresh and the gateway writes a block
    for it, so this is not a rare race: it is what looking at the dashboard
    would do to the agent's evidence.
    """
    text = read(STACK)
    match = re.search(r"\$env:LEDGER_DB_PATH\s*=\s*(.+)", text)
    assert match, "scripts/start_stack.ps1 must set LEDGER_DB_PATH explicitly"
    assignment = match.group(1)
    assert "data\\agent" not in assignment and "data/agent" not in assignment, (
        f"the demonstration stack points its ledger at the agent's database: "
        f"{assignment.strip()}")


# ---------------------------------------------------------------- self-test


def test_the_self_test_report_stays_out_of_the_reports_directory():
    """Everything in reports/ that stamps a commit is checked against git.

    `scripts/claim_matrix.py` asks whether each artefact's recorded commit is an
    ancestor of HEAD. A file written on a user's machine at install time has no
    such commit, so putting it there would turn a green provenance gate red for
    a reason that has nothing to do with provenance.
    """
    text = SELFTEST.read_text(encoding="utf-8")
    assert 'Path(config.data_dir) / "selftest.json"' in text
    assert "REPORTS" not in text, (
        "scripts/selftest.py must not write into reports/")


def test_a_skipped_self_test_counts_as_a_failure():
    """A skipped check is a failed check, including this one.

    -SkipSelfTest exists so an installation can be inspected without the live
    test, not so it can be declared finished without it.
    """
    text = read(INSTALL)
    block = text[text.find("if ($SkipSelfTest)"):text.find("} elseif (Test-Path $venvPython)")]
    assert "$script:Failures++" in block, (
        "-SkipSelfTest must leave the installer exiting non-zero: nothing else "
        "in the run demonstrates that the agent can attribute, suspend or "
        "restore anything")


def test_the_writer_is_a_separate_file_from_the_thing_that_measures_it():
    """No attack written by the same file that measures the response."""
    assert WRITER.is_file()
    text = SELFTEST.read_text(encoding="utf-8")
    assert "os.urandom(" not in text, (
        "scripts/selftest.py generates the attack payload itself; it must spawn "
        "scripts/selftest_writer.py and read the agent's ledger for the verdict")
    assert "WRITER" in text and "subprocess.Popen" in text, (
        "scripts/selftest.py no longer spawns the writer as a child process")
    assert "os.urandom(" in WRITER.read_text(encoding="utf-8")


# ------------------------------------------------- Windows-only: does it parse


@pytest.mark.skipif(platform.system() != "Windows",
                    reason="PowerShell's parser is on Windows; CI is Linux")
@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_the_powershell_parses(path: Path):
    command = (
        "$errs = $null; $toks = $null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile('{path}', "
        "[ref]$toks, [ref]$errs) | Out-Null; "
        "if ($errs) { $errs | ForEach-Object { $_.Message }; exit 1 } else { exit 0 }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"{path.name} does not parse:\n{result.stdout}"


# ------------------------------------------------------ the receipt's contract


RECEIPT_KEYS_UNINSTALL_READS = (
    "prior.audit_subcategory_was_enabled",
    "prior.security_log_max_bytes",
    "prior.data_dir",
    "applied.sacl_paths",
    "applied.data_dir_locked",
)


@pytest.mark.parametrize("key", RECEIPT_KEYS_UNINSTALL_READS)
def test_every_receipt_key_the_uninstaller_reads_is_one_the_installer_writes(key: str):
    """The receipt is the contract between the two scripts.

    An uninstaller reading a key nothing writes silently takes the "we do not
    know" branch for ever, which for the audit subcategory means never
    reverting it and for the data directory means never unlocking it.
    """
    installer = read(INSTALL)
    uninstaller = read(UNINSTALL)
    section, leaf = key.split(".")
    # Two spellings, because `prior` goes through Set-Prior - which writes only
    # if no earlier install already recorded it - and `applied` is assigned
    # directly. Both are writes.
    written = (f"$script:Receipt.{section}.{leaf}" in installer
               or f"Set-Prior '{leaf}'" in installer)
    assert written, f"install.ps1 never writes {key}"
    assert f"{section}.{leaf}" in uninstaller, f"uninstall.ps1 never reads {key}"


def test_the_self_test_uses_the_pid_the_writer_reports_not_the_one_it_inferred():
    """`Popen.pid` is the launcher's PID, not the writer's.

    `.venv\Scripts\python.exe` is a 255 KB launcher that starts the real
    interpreter as its own child. Measured: Popen.pid 28732, the writer's own
    `os.getpid()` 9976. Asserting against the first one failed an agent that had
    attributed, suspended and snapshotted the second one correctly - the test
    reporting a defect that was its own.

    The rule this project has about never guessing a PID applies to the thing
    doing the measuring too.
    """
    text = SELFTEST.read_text(encoding="utf-8")
    assert 'announced.get("pid")' in text, (
        "scripts/selftest.py must take the child PID from what the writer "
        "printed about itself")
    assert "child_pid = child.pid" not in text, (
        "scripts/selftest.py is back to inferring the writer's PID from Popen")
    assert '"pid": os.getpid()' in WRITER.read_text(encoding="utf-8"), (
        "scripts/selftest_writer.py must announce its own PID; the self-test "
        "has nothing else to go on")


def test_stopping_the_stack_kills_the_children_not_just_the_launcher():
    """`-Stop` printed "5 process(es) stopped" while all five ports were still
    listening.

    `.venv\Scripts\python.exe` is a launcher; the real interpreter is its
    child and that child holds the socket. Stopping the recorded PID alone left
    every server running under a stop that reported success - which is worse
    than one that fails, because nothing looks wrong afterwards.
    """
    text = read(STACK)
    assert "ParentProcessId = $($entry.pid)" in text, (
        "scripts/start_stack.ps1 -Stop must stop the children of each recorded "
        "PID; the launcher is not the server")
    assert "still held by" in text, (
        "-Stop must check the ports afterwards. A PID going away is the "
        "setting; the port going quiet is the effect")


def test_the_stack_will_not_call_somebody_elses_server_its_own():
    """Two services once reported healthy while bound to nothing.

    A Docker forwarder held :8001 and :8003, both native processes died on
    bind, and the health probe got a 200 from the containers. The check has to
    be "is the listener the process I started", not "did something answer".
    """
    text = read(STACK)
    assert "function Test-OwnsPort" in text
    assert "Test-OwnsPort -Port $entry.port -ProcessId $entry.pid" in text, (
        "scripts/start_stack.ps1 must confirm the listener on each port is the "
        "process it started")
