"""Entropy, magic bytes and classification - the detection core.

Covers TC-02 (ransomware-style encryption is flagged) and TC-03 (legitimate
compression is not), which is the false-positive mitigation the design doc
requires alongside raw entropy.
"""

import gzip
import io
import os
import time
import zipfile
import zlib

import pytest

import detection
from detection import (
    DEFAULT_ENTROPY_THRESHOLD,
    calculate_entropy,
    classify,
    entropy_of,
    get_magic_bytes,
    identify_container,
    looks_unreadable,
    read_magic,
    sha256_file,
)


# --------------------------------------------------------------------- entropy


def test_entropy_of_empty_data_is_zero():
    assert entropy_of(b"") == 0.0


def test_entropy_of_single_repeated_byte_is_zero():
    assert entropy_of(b"\x00" * 4096) == 0.0


def test_entropy_of_uniform_byte_distribution_is_eight():
    """Every byte value equally likely -> exactly 8 bits/byte."""
    assert entropy_of(bytes(range(256)) * 16) == 8.0


def test_entropy_of_two_equally_likely_symbols_is_one():
    assert entropy_of(b"AB" * 512) == 1.0


def test_english_text_entropy_sits_well_below_the_threshold():
    text = (b"the quick brown fox jumps over the lazy dog. " * 200)
    assert entropy_of(text) < 5.0


def test_random_bytes_entropy_sits_above_the_threshold():
    assert entropy_of(os.urandom(65536)) >= DEFAULT_ENTROPY_THRESHOLD


def test_calculate_entropy_on_missing_file_returns_zero_not_raises():
    assert calculate_entropy("/nonexistent/path/to/file.bin") == 0.0


# ----------------------------------------------------------------- magic bytes


@pytest.mark.parametrize(
    "magic,expected",
    [
        (b"PK\x03\x04hello", "zip"),
        (b"\x1f\x8b\x08\x00", "gzip"),
        (b"Rar!\x1a\x07\x00", "rar"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"BZh91AY", "bzip2"),
        (b"\x28\xb5\x2f\xfd\x00", "zstd"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff\xe0", "jpeg"),
        (b"%PDF-1.7", "pdf"),
        (b"OggS\x00\x02", "ogg"),
        (b"\x00\x00\x00\x18ftypmp42", "iso-bmff"),
    ],
)
def test_known_containers_are_identified(magic, expected):
    assert identify_container(magic) == expected


@pytest.mark.parametrize("magic", [b"", b"\x00\x00\x00\x00", b"random-noise-here", b"MZ\x90\x00"])
def test_non_container_headers_are_not_identified(magic):
    assert identify_container(magic) is None


def test_get_magic_bytes_returns_four_byte_hex(tmp_path):
    target = tmp_path / "f.bin"
    target.write_bytes(b"\x89PNG\r\n\x1a\n")
    assert get_magic_bytes(str(target)) == "89504E47"


def test_get_magic_bytes_on_missing_file_is_unknown():
    assert get_magic_bytes("/nonexistent/file") == "UNKNOWN"


# -------------------------------------------------------------- classification


def test_tc02_encrypted_looking_file_is_flagged(tmp_path):
    """TC-02: high-entropy write with no recognisable format -> suspicious."""
    target = tmp_path / "report.docx"
    target.write_bytes(os.urandom(65536))

    entropy = calculate_entropy(str(target))
    verdict = classify(str(target), entropy, read_magic(str(target)))

    assert verdict["suspicious"] is True
    assert verdict["verdict"] == "suspected_encryption"
    assert "no recognised container header" in verdict["reason"]


def test_unreadable_file_is_not_reported_as_benign(tmp_path):
    """A file we could not read is a third outcome, not a clean bill of health.

    Windows hands out deny-share handles routinely - the encrypting process,
    Defender, and the indexer all hold one at the moment the event fires. An
    unreadable file scores entropy 0.0, and calling that "benign" is how real
    encryption gets missed silently.
    """
    target = tmp_path / "report.docx"
    target.write_bytes(os.urandom(65536))

    verdict = classify(str(target), 0.0, b"", readable=False)

    assert verdict["verdict"] == "unreadable"
    assert verdict["suspicious"] is False
    assert verdict["entropy"] is None
    assert "could not be read" in verdict["reason"]


def test_unreadable_file_with_a_ransom_extension_is_still_flagged(tmp_path):
    """No bytes to score, but the name alone is evidence enough."""
    target = tmp_path / "report.docx.locked"
    target.write_bytes(os.urandom(65536))

    verdict = classify(str(target), 0.0, b"", readable=False)

    assert verdict["suspicious"] is True
    assert verdict["verdict"] == "suspicious_extension"
    assert verdict["ransom_extension"] is True


def test_looks_unreadable_separates_a_locked_file_from_an_empty_one():
    assert looks_unreadable(b"", 65536) is True    # bytes exist, we got none
    assert looks_unreadable(b"", 0) is False       # genuinely empty
    assert looks_unreadable(b"PK\x03\x04", 65536) is False


# ------------------------------------------------------- lock retry budget


@pytest.fixture
def always_locked(monkeypatch):
    """Every open raises a sharing violation, as a deny-share handle would."""

    def deny(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(detection, "open", deny, raising=False)


def test_lock_retry_stays_inside_the_detection_budget(always_locked, tmp_path):
    """Waiting for a lock must not cost more than the verdict is allowed to.

    Bounded by elapsed time, not attempt count: three attempts at 50ms of
    backoff was 150ms for a single open, and handle_event opens the same file
    twice, so a locked file measured 303ms against a 100ms target.
    """
    target = tmp_path / "locked.docx"
    target.write_bytes(b"x" * 4096)

    started = time.perf_counter()
    with pytest.raises(PermissionError):
        detection.open_for_read(str(target))
    elapsed = time.perf_counter() - started

    assert elapsed >= detection.READ_RETRY_BUDGET_SECONDS / 2, "it gave up without retrying at all"
    assert elapsed < 0.100, f"retry overran the detection target: {elapsed * 1000:.0f}ms"


def test_a_file_already_known_to_be_locked_is_not_waited_for_again(always_locked, tmp_path):
    """One event pays the budget once, not once per read helper."""
    target = tmp_path / "locked.docx"
    target.write_bytes(b"x" * 4096)

    started = time.perf_counter()
    with pytest.raises(PermissionError):
        detection.open_for_read(str(target), retry=False)
    elapsed = time.perf_counter() - started

    assert elapsed < detection.READ_RETRY_BUDGET_SECONDS / 2, f"it still waited {elapsed * 1000:.0f}ms"


def test_the_read_helpers_honour_the_no_retry_flag(always_locked, tmp_path):
    """All four degrade to their empty value without spending the budget."""
    target = tmp_path / "locked.docx"
    target.write_bytes(b"x" * 4096)
    path = str(target)

    started = time.perf_counter()
    assert calculate_entropy(path, retry=False) == 0.0
    assert read_magic(path, retry=False) == b""
    assert sha256_file(path, retry=False) is None
    assert detection.byte_statistics(path, retry=False)["printable_ratio"] == 0.0
    elapsed = time.perf_counter() - started

    assert elapsed < detection.READ_RETRY_BUDGET_SECONDS, f"four reads cost {elapsed * 1000:.0f}ms"


def test_a_directory_is_not_retried(tmp_path):
    """A directory will never become readable; waiting on it is pure latency."""
    started = time.perf_counter()
    with pytest.raises(OSError):
        detection.open_for_read(str(tmp_path))
    elapsed = time.perf_counter() - started

    assert elapsed < detection.READ_RETRY_BUDGET_SECONDS / 2


def test_tc03_legitimate_zip_is_not_flagged(tmp_path):
    """TC-03: a real ZIP is high entropy and must not be called ransomware."""
    target = tmp_path / "archive.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.bin", os.urandom(200000))
    target.write_bytes(buffer.getvalue())

    entropy = calculate_entropy(str(target))
    verdict = classify(str(target), entropy, read_magic(str(target)))

    assert entropy >= DEFAULT_ENTROPY_THRESHOLD, "test is meaningless if the zip is not high entropy"
    assert verdict["suspicious"] is False
    assert verdict["verdict"] == "benign_compressed"
    assert verdict["container_format"] == "zip"


def test_tc03_legitimate_gzip_is_not_flagged(tmp_path):
    target = tmp_path / "backup.gz"
    target.write_bytes(gzip.compress(os.urandom(200000)))

    entropy = calculate_entropy(str(target))
    verdict = classify(str(target), entropy, read_magic(str(target)))

    assert entropy >= DEFAULT_ENTROPY_THRESHOLD
    assert verdict["suspicious"] is False
    assert verdict["container_format"] == "gzip"


def test_plain_text_is_benign(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("meeting notes for the capstone review\n" * 500)

    entropy = calculate_entropy(str(target))
    verdict = classify(str(target), entropy, read_magic(str(target)))

    assert verdict["suspicious"] is False
    assert verdict["verdict"] == "benign"


def test_ransom_extension_on_high_entropy_file_overrides_container_header(tmp_path):
    """A .zip header on a `.locked` file is the interesting case - a ransomware
    family prepending a valid header must not buy its way past the check."""
    target = tmp_path / "report.docx.locked"
    target.write_bytes(b"PK\x03\x04" + os.urandom(65536))

    entropy = calculate_entropy(str(target))
    verdict = classify(str(target), entropy, read_magic(str(target)))

    assert verdict["suspicious"] is True
    assert verdict["ransom_extension"] is True


def test_ransom_extension_on_low_entropy_file_is_still_suspicious(tmp_path):
    target = tmp_path / "notes.txt.wncry"
    target.write_text("a" * 5000)

    entropy = calculate_entropy(str(target))
    verdict = classify(str(target), entropy, read_magic(str(target)))

    assert verdict["suspicious"] is True
    assert verdict["verdict"] == "suspicious_extension"


def test_threshold_is_configurable(tmp_path):
    target = tmp_path / "mid.bin"
    target.write_bytes(zlib.compress(os.urandom(4096))[:2000])

    entropy = calculate_entropy(str(target))
    lenient = classify(str(target), entropy, b"\x00\x00\x00\x00", threshold=8.5)
    strict = classify(str(target), entropy, b"\x00\x00\x00\x00", threshold=1.0)

    assert lenient["suspicious"] is False
    assert strict["suspicious"] is True


# ----------------------------------------------------------------------- hash


def test_sha256_file_matches_hashlib(tmp_path):
    import hashlib

    target = tmp_path / "f.bin"
    payload = b"hello ransomware"
    target.write_bytes(payload)

    assert sha256_file(str(target)) == hashlib.sha256(payload).hexdigest()


def test_sha256_file_is_full_64_characters(tmp_path):
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    assert len(sha256_file(str(target))) == 64


def test_sha256_file_on_missing_file_returns_none():
    assert sha256_file("/nonexistent/file") is None
