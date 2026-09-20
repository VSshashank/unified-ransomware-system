"""Phase 5's harness, and the ways a harness like this reports a lie.

Everything here runs without elevation, without the service and without an
encryptor, because what is under test is the *measuring*, not the measured.
Nine of the defects fixed in Phase 4 were in the harness rather than in the
system, and the pattern in this project is unbroken: check the thing doing the
measuring before believing the verdict.

The four that matter:

  1. an arm nobody detected must not pass       (a bound that never applied)
  2. a tool that is missing must not pass       (a skipped check is a failed one)
  3. FEBR must have a value when nothing fired  (null reads as "no damage")
  4. the attack must not be in the same file as the measurement
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CORPUS = ROOT / "scripts" / "adversary_corpus.py"
RUNNER = ROOT / "scripts" / "adversary_runner.py"
SOAK = ROOT / "scripts" / "benign_soak.py"


def source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load(path: Path):
    """Import a script by path, registered so `@dataclass` can resolve it.

    `dataclasses` looks the defining class's module up in `sys.modules` while
    deciding whether an annotation is a `ClassVar`, and a module executed
    without being registered there is not found - which surfaces as an
    `AttributeError` from inside the standard library rather than as anything
    to do with this test.
    """
    import importlib.util  # noqa: PLC0415

    name = f"_phase5_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


# ------------------------------------------------- the attack is not here

def test_the_measuring_script_contains_no_encryption():
    """§2 rule 1. The corpus is third-party tools; this file must not be one."""
    text = source(CORPUS)
    for banned in ("Cipher", "AES", "encrypt(", "Fernet", "os.urandom"):
        assert banned not in text, (
            f"{banned} appears in the script that measures the response. An "
            f"attack written by the file that measures it is not evidence.")


def test_the_runner_implements_no_encryption_either():
    """It launches binaries. Every one of them is somebody else's."""
    tree = ast.parse(source(RUNNER))
    imported = {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not (imported & {"cryptography", "Crypto", "nacl", "ssl"}), (
        f"the runner imports a crypto library: {imported}. It is supposed to "
        f"start other people's encryptors, not be one.")


def test_every_arm_names_the_binary_it_drives():
    """An arm with no third-party tool behind it is an encryptor in disguise."""
    module = load(RUNNER)

    for arm, (handler, _inplace) in module.ARMS.items():
        assert callable(handler), arm
        # Every handler's first parameter is the path to the binary it runs.
        argnames = handler.__code__.co_varnames[:handler.__code__.co_argcount]
        assert argnames[0] == "tool", (
            f"{arm}'s handler does not take a tool to run: {argnames}")


# ------------------------------------------- an arm nobody saw is a failure

def test_an_undetected_arm_cannot_pass():
    """The gate that would otherwise pass by default.

    FEBR and TTS have bounds that only apply once something has been
    suspended. An arm the agent never noticed suspends nothing, so neither
    bound is exceeded, so a verdict built only from bounds reads `ok`. That is
    exactly the shape of a gate weakened to make it pass, and the first version
    of this script had it: 7-Zip archived the protected root, deleted twenty
    decoys, and the arm was reported as within bounds.
    """
    text = source(CORPUS)
    start = text.index("within_bounds = (")
    end = text.index(")", text.index("canaries_intact", start))
    clause = text[start:end]
    assert "detected" in clause, (
        "the arm verdict does not require the agent to have detected "
        "anything; an attack nobody saw would pass it")


def test_a_missing_tool_is_a_failed_arm_not_a_skipped_one():
    """§2 rule 2, in the place it is easiest to get wrong."""
    text = source(CORPUS)
    marker = "if not tool.path:"
    assert marker in text
    block = text[text.index(marker):text.index(marker) + 500]
    assert "return result" in block
    # `ArmResult.passed` is False whenever `ran` is False, and the block never
    # sets `ran`.
    assert "result.ran = True" not in block, (
        "an arm whose tool is missing must not be marked as having run")


def test_febr_is_a_number_even_when_nothing_was_suspended():
    """`null` FEBR reads as no damage. It means the attacker got everything."""
    text = source(CORPUS)
    assert "if suspend_at is None:\n        febr = damaged" in text, (
        "FEBR must fall back to the whole damaged set when no response fired")


def test_the_run_fails_if_no_arm_was_ever_suspended():
    """§5's bound is a claim about the system, asked once across the run."""
    text = source(CORPUS)
    assert "suspended_within_bounds" in text
    assert "and suspended_within_bounds) else 1" in text, (
        "a run where nothing was ever suspended must exit non-zero, whatever "
        "the individual arms say")


# ------------------------------------------------ the ground truth is theirs

def test_attribution_is_graded_against_the_launcher_not_the_agent():
    """Grading the agent against the agent's own record proves nothing."""
    text = source(CORPUS)
    assert "answer_key" in text
    grading = text[text.index("for block in file_events"):]
    grading = grading[:grading.index("suspended_pids = ")]
    assert "in answer_key" in grading, (
        "the correct/mis-attributed split must be decided by the answer key "
        "the runner wrote, not by anything the agent said")


def test_the_runner_writes_the_answer_key_as_it_launches():
    text = source(RUNNER)
    assert "writers.record(child.pid" in text, (
        "each launched process must be recorded with the PID the OS returned")
    assert "writers.record(os.getpid()" in text, (
        "the launcher unlinks originals and owns the in-place handles, so it "
        "is a writer too and belongs in the key")


def test_the_runner_reports_its_own_pid_not_the_parents():
    """The venv trampoline has caused this twice in this project."""
    text = source(RUNNER)
    assert "os.getpid()" in text
    assert "Popen.pid" in text, (
        "the reason for reporting os.getpid() should be written down where "
        "the next person will read it")


# ------------------------------------------------- the technique by number

def test_the_atomic_arm_runs_the_published_atomic_not_a_copy_of_it():
    """T1486 is named by number in the build plan. Run it, do not rewrite it."""
    text = source(RUNNER)
    block = text[text.index("def atomic_t1486"):]
    block = block[:block.index("\nARMS = ")]
    assert "Invoke-AtomicTest T1486 -TestNumbers 8" in block, (
        "the arm must invoke Red Canary's runner against their YAML; a "
        "PowerShell transcription of the executor is a re-implementation and "
        "proves nothing an encryptor I wrote would not")
    # Past the docstring, which explains at length why -Cleanup is not used.
    body = block[block.index('"""', block.index('r"""') + 4):]
    assert "-Cleanup" not in body, (
        "the atomic's cleanup deletes the target, and the target is the "
        "operator's file - what happens to it is the restore path's question")


def test_the_atomic_arm_fails_when_the_atomics_are_absent():
    """It launches powershell.exe, which is on every Windows host.

    So `tool.path` is always satisfied and would let the arm start, run
    nothing and report green. What makes it the corpus member is Red Canary's
    YAML, and that is what has to be present.
    """
    module = load(CORPUS)
    tool = module.known_tools()["atomic"]
    assert tool.provenance, "the atomic arm declares no provenance files"
    assert any("T1486.yaml" in f for f in tool.provenance)

    text = source(CORPUS)
    assert "absent = tool.missing_provenance()" in text
    gate = text[text.index("absent = tool.missing_provenance()"):]
    gate = gate[:gate.index("return result") + len("return result")]
    assert "result.ran" not in gate, (
        "an arm whose atomic is missing must not be marked as having run")


def test_the_answer_key_covers_the_process_tree():
    """powershell -> cmd -> gpg. Only gpg writes; only powershell survives.

    An answer key holding the PowerShell host alone would score every
    correctly-named `gpg.exe` as a mis-attribution, and manufacture the one
    number this branch exists to keep at zero.
    """
    text = source(RUNNER)
    assert "class DescendantWatch" in text
    watch = text[text.index("class DescendantWatch"):]
    watch = watch[:watch.index("\ndef announce")]
    assert "children(recursive=True)" in watch
    assert '"descendant"' in watch, (
        "a descendant must be recorded under its own role, not indexed as "
        "something this script chose to start")
    # The sweep has to run once more after the arm ends: a process that
    # appeared between the last poll and the exit is still the attack's.
    assert "def stop" in watch and watch.index("self.sweep()", watch.index("def stop")) > 0


def test_the_destructive_atomics_are_excluded_on_the_record():
    """Three of the four Windows T1486 atomics are not run. Say which and why."""
    text = source(CORPUS)
    caveat = text[text.index('"_what_this_does_not_show"'):]
    caveat = caveat[:caveat.index("\n        \"generated_at\"")]
    for atomic in ("T1486-5", "T1486-9", "T1486-10"):
        assert atomic in caveat, (
            f"{atomic} is a Windows atomic for this technique and the report "
            f"does not account for it")
    assert "DiskCryptor" in caveat


# -------------------------------------------------------- the blast radius

def test_the_harness_cleans_up_even_when_it_raises():
    """Its first crash left an encrypted archive inside a watched folder."""
    text = source(CORPUS)
    assert "_CREATED.append" in text
    assert "finally:\n        emergency_cleanup(args)" in text


def test_nothing_is_killed_during_cleanup():
    """Only resumed. Everything in the key exits on its own."""
    text = source(CORPUS)
    cleanup = text[text.index("def cleanup_arm"):]
    cleanup = cleanup[:cleanup.index("\n\n\n")] if "\n\n\n" in cleanup else cleanup
    assert ".resume()" in cleanup
    assert ".kill()" not in cleanup and ".terminate()" not in cleanup, (
        "cleanup must not kill a process it did not need to")


def test_an_observed_suspension_must_be_the_process_that_was_launched():
    """A run reported TTS 12.307 s from a PID the chain had never suspended.

    The `openssl-loop` arm starts 200 processes that live about 65 ms each, and
    Windows recycles their PIDs almost at once. The watcher saw one of those
    numbers in STATUS_STOPPED and called it a suspension; it belonged to
    unrelated software by then. Ten previous defects in this project were in
    the thing doing the measuring, and this is the eleventh.
    """
    text = source(CORPUS)
    watcher = text[text.index("class SuspendWatch"):]
    watcher = watcher[:watcher.index("\n# ---")]
    assert "create_time()" in watcher, (
        "a PID observed as stopped must be checked against the creation time "
        "the runner recorded, or a recycled PID reads as a suspension")
    assert "SAME_PROCESS_TOLERANCE_S" in watcher
    assert "self.rejected" in watcher, (
        "rejected candidates must be counted and reported, not silently "
        "dropped")


def test_a_suspension_the_chain_holds_is_not_reported_as_no_suspension():
    """`gpg-loop` suspended pid 16476 and reported FEBR 200, TTS null.

    The watcher polls for a freeze and reports only what it saw, which is
    right. When it sees nothing and the ledger holds an escalation naming a
    PID the *launcher* recorded, the suspension happened and the harness has
    no time for it - and falling back to "all 200 files" says the response
    never fired.
    """
    text = source(CORPUS)
    assert "ledger_suspend_wall" in text
    block = text[text.index("ledger_suspend_wall: float | None = None"):]
    block = block[:block.index("effective_tts_s = ")]
    # The moment may come from the chain. The identity may not.
    assert "int(pid) not in answer_key" in block, (
        "a PID taken from the agent's own escalation must still be one the "
        "launcher recorded starting, or the agent nominates its own success")
    assert "suspend_moment_source" in text, (
        "a number taken from the ledger and a number observed independently "
        "are different evidence and the report must say which this is")


def test_febr_for_an_unlinking_encryptor_comes_from_the_launcher():
    """A deleted file has no mtime, so FEBR counted every one of them.

    `gpg-loop` unlinks all 200 originals, so the mtime-based count returns 200
    whenever the suspension landed - a response that saved 96 files reporting
    as one that saved none. The launcher recorded when it started each writer,
    and that record survives the deletion.
    """
    text = source(CORPUS)
    assert "febr_from_launcher" in text
    block = text[text.index("febr_from_launcher = None"):]
    block = block[:block.index("tts_from_ledger_s = None")]
    assert 'record.get("role") == "encryptor"' in block, (
        "only processes the runner launched as writers count; a descendant or "
        "the launcher itself is not one file")
    # Proved from the key, not asserted from the arm's description.
    assert "len(writers_launched) == len(files)" in block, (
        "the one-writer-per-file property must be established from the answer "
        "key, not taken from the arm's prose description of itself")
    assert "febr_from_launcher_writer_count" in text, (
        "it is published beside FEBR, never silently in place of it")


def test_a_recycled_pid_does_not_shorten_the_answer_key():
    """200 launches produced 180 distinct PIDs on this host.

    Keyed by PID, the answer key is twenty launches short of what happened.
    That is harmless for deciding *who* a process was and wrong for counting
    *how many files* the attack reached, so both views are kept.
    """
    corpus = source(CORPUS)
    assert "launches: list[dict] = []" in corpus
    assert "launches.append(record)" in corpus
    block = corpus[corpus.index("writers_launched = sorted("):]
    block = block[:block.index("one_writer_per_file = ")]
    assert "for record in launches" in block, (
        "counting writers from the PID-keyed dict loses every recycled PID")

    # And the runner must write every launch, not collapse repeats.
    runner = source(RUNNER)
    assert 'if role == "descendant" and pid in self.recorded:' in runner, (
        "deduplication belongs to the descendant sweep; a launch is always "
        "recorded, or the key is short by however many PIDs Windows reused")


def test_the_arms_stdout_cannot_fill_the_pipe_that_nobody_reads():
    """A blocked writer reports the timeout as if it were a measurement.

    The measuring script holds each arm's stdout. `Invoke-AtomicTest`
    announces every invocation through `Write-Host`, which bypasses the
    pipeline, so `| Out-Null` does not stop it - two hundred invocations put
    tens of kilobytes into a 64 KB buffer.
    """
    runner = source(RUNNER)
    assert "6>$null" in runner, (
        "Write-Host goes to the information stream; only a stream-6 "
        "redirection suppresses it")
    corpus = source(CORPUS)
    drain = corpus[corpus.index("def read_announcement"):]
    drain = drain[:drain.index("reader = threading.Thread")]
    assert "for _ in child.stdout:" in drain, (
        "the announcement is the first line and the rest must still be read, "
        "or the pipe fills and the arm hangs")
    # And only one reader on that pipe.
    assert "child.communicate(" not in corpus, (
        "communicate() is a second reader on a stdout the drain thread owns")


def test_the_chain_is_not_read_before_the_agent_has_finished_writing():
    """Five of six arms published `detected=False` while the agent was behind.

    The agent went on to write 398, 351 and 459 `suspected_encryption` blocks
    for three of those arms after the harness had already looked and moved on.
    A chain read before its writer has caught up is not evidence about the
    writer, and reporting the silence as a property of the system is the
    harness answering a question it never asked.
    """
    text = source(CORPUS)
    assert "def wait_for_the_agent_to_catch_up" in text
    probe = text[text.index("def wait_for_the_agent_to_catch_up"):]
    probe = probe[:probe.index("# ---------")]
    assert "protected /" in probe, (
        "the sentinel has to be written where the agent is watching, or it "
        "proves nothing about the queue")
    assert "_CREATED.append" in probe, (
        "a file this script puts in the protected path must be removable "
        "after a crash like every other one")

    # An arm read too early is a failed arm, not a quiet one.
    clause = text[text.index("within_bounds = ("):]
    clause = clause[:clause.index("canaries_intact", 0) if False else clause.index(")")]
    assert 'drain["drained"]' in clause, (
        "an arm whose chain was read before the agent caught up measured "
        "nothing and must not be within bounds")


def test_a_root_scoped_arm_is_graded_on_the_files_it_actually_had():
    """Its five mis-attributions were another workload's backlog.

    `sevenzip-root` points at the protected root, so a prefix match on the
    root swept in `makecab.exe` and `git.exe` events the benign soak had
    produced an hour earlier and the agent was still working through. The
    agent named both correctly. The answer key belonged to a different run,
    so five correct answers were published as mis-attributions.
    """
    text = source(CORPUS)
    assert "if root_scope:" in text
    block = text[text.index("if root_scope:", text.index("archive_path = ")):]
    block = block[:block.index("    file_events = ")]
    assert "scoped = {str(path).lower() for path in before}" in block, (
        "scope is the snapshot the arm was taken against, not the directory "
        "it was pointed at")
    assert "path in scoped" in block


def test_a_refused_unlink_is_counted_not_swallowed():
    """44 of 200 originals survived `openssl-loop` and read as untouched."""
    runner = source(RUNNER)
    assert "UNLINK_FAILURES" in runner
    assert "def _unlink" in runner
    block = runner[runner.index("def _unlink"):]
    block = block[:block.index("\ndef ")]
    assert "UNLINK_FAILURES.append" in block
    # And no arm may go back to swallowing them.
    for arm in ("def openssl_loop", "def gpg_loop"):
        body = runner[runner.index(arm):]
        body = body[:body.index("\ndef ", 10)]
        swallowed = "except OSError:" + chr(10) + " " * 12 + "pass"
        assert swallowed not in body, (
            f"{arm} swallows a refused unlink again")


def test_the_bound_is_read_against_whichever_moment_exists():
    text = source(CORPUS)
    assert "effective_tts_s = tts_s if tts_s is not None else tts_from_ledger_s" in text
    assert "effective_tts_s is not None" in text[text.index("tts_ok = "):
                                                 text.index("tts_ok = ") + 220]


def test_recovery_has_a_duration_even_with_no_suspension():
    """MTTR is suspend-to-restore. With no suspend it is null, and recovery is not."""
    text = source(CORPUS)
    assert "recovery_s_first_write_to_last_verified" in text


def test_the_restore_rate_comes_from_the_agents_own_configuration():
    """A number typed in here goes stale the moment the threshold moves."""
    text = source(CORPUS)
    block = text[text.index("def restore_interval_s"):]
    block = block[:block.index("\ndef ")]
    assert "velocity_path_threshold" in block
    assert "velocity_window_s" in block


# --------------------------------------------------------- the benign soak

def test_the_soak_counts_suspensions_not_alerts():
    """"Suspends per hour" is the metric. Alerts are reported beside it."""
    text = source(SOAK)
    assert "false_positive_suspensions" in text
    assert "flagged_file_events" in text, (
        "alerts belong in the artefact too - a corpus that raises a thousand "
        "and suspends nothing is a different system")


def test_the_soak_names_what_it_could_not_run():
    """Six members of the corpus are not installable here. Say which."""
    module = load(SOAK)

    for name in ("ffmpeg-transcode", "veracrypt-container", "windows-update",
                 "visual-studio-build", "browser-cache-churn", "onedrive-sync"):
        assert name in module.NOT_INSTALLED, (
            f"{name} is named in the build plan and is not accounted for")
        assert len(module.NOT_INSTALLED[name]) > 20, (
            f"{name} is listed without a reason")


def test_the_soak_says_so_when_it_cannot_clean_up_after_itself():
    """It once announced removing a 139 MB clone it had left in place.

    `rmtree(..., ignore_errors=True)` followed by `print("removed ...")` is a
    false statement about the protected path, and the next thing scheduled
    there archives that path and counts what it finds as damage.
    """
    text = source(SOAK)
    teardown = text[text.index("if not args.keep:"):]
    assert "ignore_errors=True" not in teardown, (
        "an ignored error followed by a confident message is the defect; _prune may still ignore them, the final teardown may not")
    assert "def _force_rmtree" in text
    block = text[text.index("def _force_rmtree"):]
    block = block[:block.index("\ndef ")]
    assert "stat.S_IWRITE" in block, (
        "git marks its objects read-only and Windows will not unlink a "
        "read-only file; clearing the bit is the whole fix")
    assert "return not target.exists()" in block, (
        "the caller has to be told whether it actually went")
    assert "COULD NOT REMOVE" in text


def test_the_soak_refuses_to_report_a_rate_it_did_not_measure():
    text = source(SOAK)
    assert "if not any(w.runs for w in CORPUS)" in text, (
        "a soak where no workload ran measured nothing and must say so")


def test_the_soak_runs_inside_the_protected_path():
    """Benign work done where the agent is not watching measures nothing."""
    text = source(SOAK)
    assert "workdir = protected /" in text


# ----------------------------------------------------------- the artefacts

@pytest.mark.parametrize("name", ["phase5_attack_corpus", "phase5_benign_soak"])
def test_the_report_says_what_it_does_not_show(name):
    """Every artefact in this project carries its own limits. These too."""
    path = ROOT / "reports" / f"{name}.json"
    if not path.is_file():
        pytest.skip(f"{path.name} has not been generated on this host yet")
    report = json.loads(path.read_text(encoding="utf-8"))
    assert "_what_this_does_not_show" in report
    assert len(report["_what_this_does_not_show"]) > 40


def test_the_attack_report_publishes_mis_attribution():
    """§5: "Mis-attribution must be 0." A number that is not there is not 0."""
    path = ROOT / "reports" / "phase5_attack_corpus.json"
    if not path.is_file():
        pytest.skip("phase5_attack_corpus.json has not been generated yet")
    report = json.loads(path.read_text(encoding="utf-8"))
    assert "total_misattributions" in report["summary"]
    assert report["summary"]["total_misattributions"] == 0, (
        "a mis-attributed PID in a hash chain is the defect this whole branch "
        "exists to fix")
    for arm in report["arms"]:
        if arm["ran"]:
            assert arm["metrics"]["attribution_misattributed"] == 0, arm["arm"]
