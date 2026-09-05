"""The authorship record Table 9.9 requires (P8.1).

Table 9.9 permits the sentence "The project team designed and implemented..."
only against `PROJECT_IMPLEMENTATION_RECORD.md`. This script generates the
evidence that document quotes, so the authorship claim rests on the repository's
own history rather than on anyone's recollection.

Everything here is read from git. Nothing is entered by hand except the mapping
from a commit email to a set of initials, which is checked against the
`feature/<INITIALS>-<topic>` branch convention §9.15 records: each set of
initials must own at least one branch under that convention, or the mapping is
wrong and the script says so.

Three things are measured that a thesis is otherwise tempted to assert:

1. **Who wrote which part of the system**, by first-authorship of each file and
   by insertions per area. First-authorship answers "who created this", which is
   the question an authorship record is asked; insertions answer "who carried
   it", which is a different question and is reported separately because the two
   disagree.
2. **How lopsided the contribution is.** The record states the actual split
   rather than a four-way division of labour that the history does not show.
3. **How much of it is AI-assisted.** Commits carrying a `Co-Authored-By:
   Claude` trailer are counted and reported as a proportion. A thesis that
   claims a team built something must say this, and the number is large.

Usage:

    python scripts/implementation_record.py
    URDS_WRITE_REPORTS=1 python scripts/implementation_record.py

Writes reports/implementation_record.json only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
OUT = REPORTS / "implementation_record.json"

# The only hand-entered table in this script. Each entry is checked against the
# branch convention below; an entry that owns no branch is reported as
# unverified rather than silently trusted.
CONTRIBUTORS: dict[str, dict[str, str]] = {
    "nikhil.k3312@gmail.com": {"initials": "NI", "name": "nikhil-k3312"},
    "vsshashank23@gmail.com": {"initials": "SH", "name": "Shashank V S"},
    "89789147+vsshashank@users.noreply.github.com": {"initials": "SH", "name": "Shashank V S"},
    "8.9789147e+07+vsshashank@users.noreply.github.com": {"initials": "SH", "name": "Shashank V S"},
    "shettyapeksha5858@gmail.com": {"initials": "AS", "name": "apekshashetty22"},
    "siddhisubhashgaikwad@gmail.com": {"initials": "SI", "name": "siddhi subhash gaikwad"},
}

AI_TRAILER = "Co-Authored-By: Claude"


def git(*args: str) -> str:
    done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    return done.stdout


def initials_for(email: str) -> str:
    return CONTRIBUTORS.get(email.lower(), {}).get("initials", "UNMAPPED")


def area_of(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    if parts[0] == "services" and len(parts) > 1:
        return f"services/{parts[1]}"
    if parts[0] in {"scripts", "docs", "src", "reports", "models", "data"}:
        return parts[0]
    if parts[0] == ".github":
        return ".github"
    return "root"


# --------------------------------------------------------------------------
# Commit-level history
# --------------------------------------------------------------------------

def commits(refspec: str) -> list[dict]:
    """Every non-merge commit reachable from `refspec`, with numstat."""
    raw = git("log", refspec, "--no-merges", "--numstat",
              "--format=%x01%H%x02%ae%x02%ad%x02%s%x02%b%x03", "--date=short")
    out: list[dict] = []
    current: dict | None = None
    for chunk in raw.split("\x01"):
        if not chunk.strip():
            continue
        header, _, rest = chunk.partition("\x03")
        fields = header.split("\x02")
        if len(fields) < 5:
            continue
        sha, email, date, subject, body = fields[0], fields[1], fields[2], fields[3], fields[4]
        current = {
            "sha": sha,
            "email": email.lower(),
            "initials": initials_for(email),
            "date": date,
            "subject": subject,
            "ai_assisted": AI_TRAILER in body,
            "files": [],
        }
        for line in rest.splitlines():
            cols = line.split("\t")
            if len(cols) == 3 and cols[0] != "-":
                current["files"].append({"added": int(cols[0]),
                                         "deleted": int(cols[1]),
                                         "path": cols[2]})
        out.append(current)
    return out


def first_authors(history: list[dict]) -> dict[str, str]:
    """Initials of whoever first added each path still present in the tree."""
    tracked = set(git("ls-files").split("\n"))
    creator: dict[str, str] = {}
    for commit in reversed(history):          # oldest first
        for entry in commit["files"]:
            path = entry["path"]
            if path in tracked and path not in creator:
                creator[path] = commit["initials"]
    return creator


def branch_convention() -> dict[str, list[str]]:
    """Branches following §9.15's feature/<INITIALS>-<topic> convention."""
    owned: dict[str, list[str]] = collections.defaultdict(list)
    for line in git("branch", "-a", "--format=%(refname:short)").split("\n"):
        name = line.strip()
        for remote_prefix in ("remotes/origin/", "origin/"):
            if name.startswith(remote_prefix):
                name = name[len(remote_prefix):]
                break
        if not name or name.startswith("HEAD"):
            continue
        for prefix in ("feature/", "feat/"):
            if name.startswith(prefix):
                tail = name[len(prefix):]
                head, _, _ = tail.partition("-")
                if head.isupper() and 2 <= len(head) <= 3:
                    if name not in owned[head]:
                        owned[head].append(name)
    return {key: sorted(value) for key, value in sorted(owned.items())}


def build() -> dict:
    head = commits("HEAD")
    everything = commits("--all")
    seen: set[str] = set()
    allrefs = [c for c in everything if not (c["sha"] in seen or seen.add(c["sha"]))]

    creator = first_authors(head)
    convention = branch_convention()

    by_initials: dict[str, dict] = {}
    known = sorted({v["initials"] for v in CONTRIBUTORS.values()})
    for who in known:
        mine = [c for c in head if c["initials"] == who]
        mine_all = [c for c in allrefs if c["initials"] == who]
        insertions: collections.Counter = collections.Counter()
        for commit in mine:
            for entry in commit["files"]:
                insertions[area_of(entry["path"])] += entry["added"]
        files_created = collections.Counter(
            area_of(path) for path, owner in creator.items() if owner == who)
        by_initials[who] = {
            "name": next(v["name"] for v in CONTRIBUTORS.values()
                         if v["initials"] == who),
            "commits_on_head": len(mine),
            "commits_all_refs": len(mine_all),
            "first_commit": min((c["date"] for c in mine_all), default=None),
            "last_commit": max((c["date"] for c in mine_all), default=None),
            "insertions_by_area": dict(insertions.most_common()),
            "files_first_authored_by_area": dict(files_created.most_common()),
            "files_first_authored_total": sum(files_created.values()),
            "branches_under_the_convention": convention.get(who, []),
            "convention_verified": bool(convention.get(who)),
            "ai_assisted_commits_on_head": sum(1 for c in mine if c["ai_assisted"]),
        }

    unmapped = sorted({c["email"] for c in allrefs if c["initials"] == "UNMAPPED"})
    ai_head = sum(1 for c in head if c["ai_assisted"])

    return {
        "schema": "urds.implementation_record.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commit": git("rev-parse", "HEAD").strip(),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD").strip(),
        "what_this_is": (
            "The evidence behind the Table 9.9 sentence 'The project team "
            "designed and implemented...'. Read from git history; the only "
            "hand-entered table is the email-to-initials mapping, and each set "
            "of initials is checked against the feature/<INITIALS>-<topic> "
            "branch convention recorded in NOVELTY_PROOF_PLAN.md section 9.15."
        ),
        "totals": {
            "commits_on_head": len(head),
            "commits_all_refs": len(allrefs),
            "tracked_files": len([p for p in git("ls-files").split("\n") if p]),
            "files_with_a_first_author": len(creator),
            "contributors": len(by_initials),
            "unmapped_emails": unmapped,
        },
        "ai_assistance": {
            "trailer": AI_TRAILER,
            "commits_on_head_with_the_trailer": ai_head,
            "commits_on_head": len(head),
            "proportion": round(ai_head / len(head), 4) if head else None,
            "first_such_commit": min(
                (c["date"] for c in head if c["ai_assisted"]), default=None),
            "statement": (
                "Commits carrying the trailer were produced with an AI "
                "assistant in the loop, under the named author's account and "
                "with the named author accepting each change. The proportion "
                "is reported because a thesis that claims a team built "
                "something has to say how it was built."
            ),
        },
        "by_contributor": by_initials,
        "branch_convention": convention,
        "what_this_does_not_show": [
            "Design discussions, reviews and pair work leave no commit of "
            "their own, so a contributor's commit count understates their "
            "share of the design.",
            "First-authorship credits whoever committed a file first, which "
            "is not always whoever wrote it - a file added in a squashed "
            "import commit is credited to the importer.",
            "Insertion counts include generated reports and vendored data, so "
            "they measure volume rather than effort. They are reported by area "
            "so a reader can discount reports/ and models/ if they choose.",
            "The record covers this repository only. Work carried out "
            "elsewhere - reading, planning, the written report - is invisible "
            "to it.",
        ],
    }


def main() -> int:
    record = build()

    print(f"{'':4s} {'commits':>8s} {'files 1st':>10s} {'AI':>5s}  branches")
    print("-" * 78)
    for who, row in sorted(record["by_contributor"].items(),
                           key=lambda kv: -kv[1]["commits_on_head"]):
        mark = "" if row["convention_verified"] else "  (no branch under the convention)"
        print(f"{who:4s} {row['commits_on_head']:8d} "
              f"{row['files_first_authored_total']:10d} "
              f"{row['ai_assisted_commits_on_head']:5d}  "
              f"{', '.join(row['branches_under_the_convention']) or '-'}{mark}")
    print("-" * 78)
    totals = record["totals"]
    ai = record["ai_assistance"]
    print(f"{totals['commits_on_head']} commits on HEAD, "
          f"{totals['commits_all_refs']} across all refs, "
          f"{totals['tracked_files']} tracked files")
    print(f"AI-assisted: {ai['commits_on_head_with_the_trailer']} of "
          f"{ai['commits_on_head']} commits on HEAD "
          f"({ai['proportion']:.1%}), first on {ai['first_such_commit']}")
    if totals["unmapped_emails"]:
        print(f"UNMAPPED emails: {totals['unmapped_emails']}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="") as handle:
        json.dump(record, handle, indent=2)
        handle.write("\n")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
