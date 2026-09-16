r"""Joining a path onto a snapshot root, for both kinds of root.

This is the regression for a bug that survived every existing recovery test and
was found only by creating a real shadow copy on a real elevated host.

WHAT HAPPENED

`to_relative` normalises separators to `/`, and it must: the Response service
runs in a Linux container, where a backslash is an ordinary filename character
and an unconverted Windows path joins into one oddly-named file rather than a
path into a directory. That part is right and is tested in `test_recovery.py`.

A real Windows shadow copy is addressed through its device object,
`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`. The `\\?\` prefix means
*take this path verbatim*, and verbatim includes **not** converting `/` to `\`.
So the forward slashes `to_relative` produces stopped being separators, the
joined path did not resolve, and `restore_file` reported the file as "not
present in the snapshot" - for a file that was in the snapshot.

WHY NO TEST CAUGHT IT

Every recovery test uses the dev fallback root, which is an ordinary directory
where both separators resolve. The device-object branch had never executed,
because reaching it needs an elevated shell to create a shadow copy - and the
acceptance row for snapshot-backed restore was carried as "not measured" for
exactly that reason. The gap in the evidence and the bug were the same gap.

`test_a_verbatim_root_needs_backslashes` is the one that fails against the old
code. It asserts the platform behaviour directly rather than trusting the
description above, so if Windows ever changes it, the test says so.
"""

from __future__ import annotations

import ntpath
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from recovery.recovery import (  # noqa: E402
    VERBATIM_PREFIX,
    join_under_snapshot,
    to_relative,
)

WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="verbatim paths are a Windows construct")


# ----------------------------------------------- the platform fact underneath


@WINDOWS_ONLY
def test_a_verbatim_root_needs_backslashes(tmp_path):
    """The measurement the fix rests on, taken rather than assumed.

    Under `\\\\?\\`, a backslash separates and a forward slash does not. If this
    ever stops being true, this test is where it shows up.
    """
    probe = tmp_path / "probe.txt"
    probe.write_text("x")

    verbatim_dir = VERBATIM_PREFIX + str(tmp_path)

    assert os.path.isfile(verbatim_dir + "\\probe.txt"), "backslash must resolve under \\\\?\\"
    assert not os.path.isfile(verbatim_dir + "/probe.txt"), (
        "forward slash resolving under \\\\?\\ would mean Windows changed; "
        "the separator fix in join_under_snapshot is then unnecessary"
    )
    # ...and without the prefix, both work. This is the contrast that makes the
    # dev-fallback tests pass while the real device object fails.
    assert os.path.isfile(str(tmp_path) + "\\probe.txt")
    assert os.path.isfile(str(tmp_path) + "/probe.txt")


# ------------------------------------------------------------------- the join


def test_b_a_device_object_root_gets_backslashes():
    root = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy11"
    joined = join_under_snapshot(root, "Unified_Ransomware_Project/data/report.docx")

    assert "/" not in joined, f"a forward slash survived into a verbatim path: {joined!r}"
    assert joined == root + r"\Unified_Ransomware_Project\data\report.docx"


def test_c_an_ordinary_root_is_left_alone():
    """The Linux container's case, which was never broken and must not become so."""
    root = "/app/snapshots/snap-1"
    joined = join_under_snapshot(root, "data/report.docx")

    assert joined == os.path.join(root, "data/report.docx")


@WINDOWS_ONLY
def test_d_an_ordinary_windows_root_is_left_alone(tmp_path):
    probe_dir = tmp_path / "data"
    probe_dir.mkdir()
    (probe_dir / "report.docx").write_text("x")

    joined = join_under_snapshot(str(tmp_path), "data/report.docx")

    assert os.path.isfile(joined), "a plain Windows root resolves either separator"


# --------------------------------------------- the two functions, end to end


@WINDOWS_ONLY
def test_e_a_windows_path_survives_the_full_round_trip(tmp_path):
    """`to_relative` then `join_under_snapshot`, against a real verbatim root.

    This is `restore_file`'s exact source computation, and it is the assertion
    that failed on the live shadow copy - reproduced here without needing one.
    `tmp_path` stands in for the shadow copy's device object: an ordinary
    directory addressed verbatim, which is the property that breaks the join.
    """
    # The file as it exists inside the "snapshot".
    inside = tmp_path / "data" / "important.docx"
    inside.parent.mkdir(parents=True)
    inside.write_bytes(b"board minutes")

    # The file as the Monitor reports it: a full Windows path on a real volume.
    reported_by_the_monitor = r"D:\data\important.docx"

    source = join_under_snapshot(
        VERBATIM_PREFIX + str(tmp_path),
        to_relative(reported_by_the_monitor),
    )

    assert os.path.isfile(source), (
        f"restore_file would report 'not present in the snapshot' for {source!r}"
    )
    assert Path(source).read_bytes() == b"board minutes"


def test_f_to_relative_still_emits_forward_slashes():
    """The Linux behaviour the fix must not disturb."""
    assert to_relative(r"D:\data\report.docx") == "data/report.docx"
    assert to_relative("/data/report.docx") == "data/report.docx"
