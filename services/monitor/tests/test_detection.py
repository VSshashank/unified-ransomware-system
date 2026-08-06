"""Entropy, magic bytes and classification - the detection core.

Covers TC-02 (ransomware-style encryption is flagged) and TC-03 (legitimate
compression is not), which is the false-positive mitigation the design doc
requires alongside raw entropy.
"""

import gzip
import io
import os
import zipfile
import zlib

import pytest

from detection import (
    DEFAULT_ENTROPY_THRESHOLD,
    calculate_entropy,
    classify,
    entropy_of,
    get_magic_bytes,
    identify_container,
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
