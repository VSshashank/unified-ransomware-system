"""The child process the installation self-test asks the agent to catch.

Separate from `scripts/selftest.py` on purpose. The self-test measures what the
agent did; if the same file also performed the write, the pair would be one
program marking its own homework, and this project has a rule against exactly
that (see the ground rules in docs/, and `reports/` for what the real
acceptance runs against instead).

What it is, stated plainly so nobody mistakes it for an experiment:

    This is a smoke test of one installation. It writes one high-entropy file
    over one path it was told to write over, and then waits. It is not the
    attack corpus, it does not resemble a real encryptor beyond the one
    property the detector keys on, and no measurement in this repository's
    evidence is produced by it. The corpus lives in `corpus/` and the arms that
    use it are in `scripts/three_arm_experiment.py`.

Why it stays alive after writing: a response gated on a Windows audit record
cannot reach a process that has already exited, and delivery on that channel
was measured at 600-1010 ms (reports/attribution_lag.json). A writer that
exits immediately is not a harder test, it is an untestable one - that is the
finding recorded for arm A1, not a property of this script. It sleeps so the
question under test is "does the agent suspend the writer", not "can a
suspend outrun process exit".

    python scripts/selftest_writer.py --target <path> --bytes 1048576 --hold 60

Prints one JSON line to stdout, then holds. Exits 0 when the hold elapses, or
when it is terminated - which is the expected ending, since the point is to be
caught.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True,
                        help="the file to overwrite with high-entropy bytes")
    parser.add_argument("--bytes", type=int, default=1024 * 1024)
    parser.add_argument("--hold", type=float, default=60.0,
                        help="seconds to stay alive after the write")
    args = parser.parse_args(argv)

    payload = os.urandom(args.bytes)

    started = time.time()
    with open(args.target, "wb") as handle:
        handle.write(payload)
        handle.flush()
        # The audit record follows the write reaching the filesystem, not the
        # buffer. Without this the agent can be asked about a write the kernel
        # has not seen yet.
        os.fsync(handle.fileno())
    finished = time.time()

    print(json.dumps({
        "pid": os.getpid(),
        "target": args.target,
        "bytes": len(payload),
        "write_started": started,
        "write_finished": finished,
        "holding_for_s": args.hold,
    }), flush=True)

    # A suspended process does not run this loop; it resumes inside it. Short
    # sleeps rather than one long one so the process is responsive to a
    # terminate, and so a resume is followed by an exit rather than by another
    # minute of nothing.
    deadline = time.monotonic() + args.hold
    while time.monotonic() < deadline:
        time.sleep(0.05)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
