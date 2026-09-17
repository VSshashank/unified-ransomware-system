#!/usr/bin/env bash
# Run the suite the way CI runs it, and print a total that can be quoted.
#
# A single root-level `pytest` cannot collect this repository. Each service
# directory puts its own `app.py`/`main.py` on `sys.path`, so one process would
# import whichever came first and the rest would fail at collection;
# .github/workflows/tests.yml says so, measured it (19 failed and 113
# collection errors in one pass), and runs each service as its own job.
#
# That is how a commit message came to report `852 passed, 2 skipped` for a
# tree in which `agent/tests/test_phase3.py` was red: the figure was measured
# before the artefact that test pins was rewritten, and reproducing it by hand
# afterwards was awkward enough not to be done. See docs/CORRECTIONS.md
# correction 9. This script makes it one command, so the number in a commit
# message is produced rather than remembered.
#
#     bash scripts/run_all_tests.sh
#
# Exits non-zero if any group is red.
#
# Two things the first draft of this file got wrong, both found by running it:
#
#   - it summed the per-group counts with `bc`, which is not installed in Git
#     Bash on the host this project is developed on. Every count parsed as 0,
#     so `TOTAL` read `0 passed, 0 failed` under six groups of green output -
#     and, worse, `red_groups` could never increment, so the script exited 0
#     whatever pytest did. A false-green guard that was itself a false green.
#     There is no `bc` here now, and a group whose summary line says "passed"
#     but parses to zero is treated as red rather than as empty.
#   - it looked for `services/recovery` and `services/ml_service`, neither of
#     which exists, and so never ran `services/ml-engine`, which CI does. The
#     list below is now the workflow's matrix, spelled the way the directories
#     are spelled. `services/dashboard` is absent from it because it contains
#     no tests, not by oversight.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1

# The interpreter that has the test dependencies. The repo venv if present,
# otherwise whatever `python` is on PATH.
if [ -x "$REPO/.venv/Scripts/python.exe" ]; then
    PY="$REPO/.venv/Scripts/python.exe"          # Windows
elif [ -x "$REPO/.venv/bin/python" ]; then
    PY="$REPO/.venv/bin/python"                  # POSIX
else
    PY="${PYTHON:-python}"
fi

total_pass=0 total_fail=0 total_skip=0 red_groups=0 missing_groups=0

summarise() {
    # pytest's own last line, which is the only place it states the totals.
    grep -E "passed|failed|error|no tests ran" | tail -1
}

count_in() {
    # $1 is pytest's one-line summary, in which each keyword appears at most
    # once. Shell arithmetic only - see the header.
    local n
    n=$(grep -oE "[0-9]+ $2" <<<"$1" | head -1 | grep -oE "^[0-9]+")
    echo "${n:-0}"
}

run_group() {
    local label="$1" dir="$2"; shift 2
    local line
    line=$( cd "$dir" && "$PY" -m pytest -q -p no:cacheprovider "$@" 2>&1 | summarise )

    if [ -z "$line" ]; then
        printf '%-24s %s\n' "$label" "no result (collection failed?)"
        red_groups=$((red_groups + 1))
        return
    fi

    local p f e s
    p=$(count_in "$line" passed)
    f=$(count_in "$line" failed)
    e=$(count_in "$line" "errors?")
    s=$(count_in "$line" skipped)

    # A line that says "passed" and parses to nothing means the parser is
    # broken, not that the group is empty. Do not let that read as green.
    if [ "$p" -eq 0 ] && [ "$f" -eq 0 ] && [ "$e" -eq 0 ] && grep -q "passed" <<<"$line"; then
        printf '%-24s %s\n' "$label" "$line   <- COULD NOT PARSE THIS LINE"
        red_groups=$((red_groups + 1))
        return
    fi

    total_pass=$((total_pass + p))
    total_fail=$((total_fail + f + e))
    total_skip=$((total_skip + s))
    if [ $((f + e)) -gt 0 ]; then red_groups=$((red_groups + 1)); fi
    printf '%-24s %s\n' "$label" "$line"
}

echo "suite: one group per importable root, as .github/workflows/tests.yml runs them"
echo

# The workflow's matrix, in its order.
for svc in gateway ledger monitor ml-engine response; do
    if [ -d "services/$svc" ]; then
        run_group "services/$svc" "services/$svc"
    else
        printf '%-24s %s\n' "services/$svc" "MISSING - CI runs this group"
        missing_groups=$((missing_groups + 1))
    fi
done

run_group "agent/tests" "$REPO" agent/tests

echo
printf 'TOTAL  %d passed, %d failed, %d skipped   (%d group(s) red)\n' \
       "$total_pass" "$total_fail" "$total_skip" "$red_groups"

if [ "$missing_groups" -gt 0 ]; then
    echo
    echo "$missing_groups group(s) CI runs are missing here; this total is not the suite."
    exit 1
fi
if [ "$red_groups" -gt 0 ]; then
    echo
    echo "A red group is a red suite. Do not quote the passing count on its own."
    exit 1
fi
exit 0
