"""NI Week 5-8 deliverable: "Extract 50+ features from PE files" (Table 5.4).

Tested against real Portable Executables taken from the running system - the
Python interpreter and the Windows DLLs next to it - rather than a hand-built
fixture. A synthetic PE would only prove the parser can read something this test
also wrote; a real signed system binary exercises resources, relocations,
debug directories and a populated import table.

On a host with no PEs to hand, the tests that need one skip rather than pretend.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pe_features import (
    FEATURE_COUNT,
    empty_pe_features,
    extract_pe_features,
    is_pe,
    suspicious_api_names,
)

REQUIRED_FEATURE_MINIMUM = 50  # Table 5.4


def _real_pe_files() -> list[Path]:
    """Real PEs: the interpreter, plus DLLs shipped beside it."""
    candidates = [Path(sys.executable)]
    exe_dir = Path(sys.executable).parent
    candidates.extend(sorted(exe_dir.glob("*.dll"))[:3])
    if os.name == "nt":
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        for name in ("kernel32.dll", "advapi32.dll"):
            candidate = system32 / name
            if candidate.exists():
                candidates.append(candidate)
    return [p for p in candidates if p.exists() and is_pe(str(p))]


REAL_PES = _real_pe_files()
needs_pe = pytest.mark.skipif(not REAL_PES, reason="no Portable Executable available on this host")


# ------------------------------------------------------- the 50+ requirement


def test_the_pipeline_extracts_more_than_fifty_features():
    """The deliverable is a number, so assert the number."""
    assert FEATURE_COUNT >= REQUIRED_FEATURE_MINIMUM, (
        f"pipeline yields {FEATURE_COUNT} features, Table 5.4 requires {REQUIRED_FEATURE_MINIMUM}+"
    )


@needs_pe
def test_a_real_pe_produces_every_declared_feature():
    """The declared column list and what the extractor returns must not drift."""
    features = extract_pe_features(str(REAL_PES[0]))
    assert set(features) == set(empty_pe_features()), (
        "declared feature names and extracted keys disagree: "
        f"missing={set(empty_pe_features()) - set(features)}, extra={set(features) - set(empty_pe_features())}"
    )
    assert len(features) >= REQUIRED_FEATURE_MINIMUM


@needs_pe
def test_the_vector_has_a_fixed_shape_across_different_inputs(tmp_path):
    """A model cannot take a dict whose keys depend on the file."""
    text = tmp_path / "notes.txt"
    text.write_bytes(b"not a PE at all\n" * 100)

    shapes = {tuple(sorted(extract_pe_features(str(p)))) for p in REAL_PES}
    shapes.add(tuple(sorted(extract_pe_features(str(text)))))
    assert len(shapes) == 1, "feature vector shape varies between inputs"


# ----------------------------------------------------------- real PE values


@needs_pe
def test_values_are_measured_not_placeholders():
    """Every previous version of pe_imports_count on this project was either
    random or absent. These are real header values with known constraints."""
    pe_path = str(REAL_PES[0])
    features = extract_pe_features(pe_path)

    assert features["is_pe"] == 1
    assert features["pe_number_of_sections"] > 0
    assert features["pe_size_of_image"] > 0
    assert features["pe_file_size"] == os.path.getsize(pe_path)
    assert features["pe_machine"] in (0x014C, 0x8664, 0xAA64), f"unexpected machine {features['pe_machine']:#x}"
    assert features["pe_optional_magic"] in (0x10B, 0x20B)
    assert features["pe_address_of_entry_point"] >= 0
    assert 0.0 <= features["pe_section_entropy_mean"] <= 8.0
    assert features["pe_section_entropy_min"] <= features["pe_section_entropy_max"]
    assert features["pe_executable_sections"] >= 1, "a PE with no executable section is not plausible"


@needs_pe
def test_extraction_is_deterministic():
    """The bug that made this necessary: /features returned a random
    pe_imports_count, so two calls for the same file disagreed."""
    pe_path = str(REAL_PES[0])
    assert extract_pe_features(pe_path) == extract_pe_features(pe_path)


@needs_pe
def test_imports_are_actually_counted():
    """At least one of the real PEs must have a populated import table -
    otherwise the import features are untested no matter how green this file is."""
    counts = [extract_pe_features(str(p))["pe_imports_count"] for p in REAL_PES]
    assert max(counts) > 0, f"no imports found in any of {[p.name for p in REAL_PES]}"

    with_imports = next(p for p in REAL_PES if extract_pe_features(str(p))["pe_imports_count"] > 0)
    features = extract_pe_features(str(with_imports))
    assert features["pe_imported_dll_count"] > 0
    assert features["pe_imports_count"] >= features["pe_imported_dll_count"]


@pytest.mark.skipif(os.name != "nt", reason="kernel32.dll is Windows-only")
def test_behavioural_api_groups_are_detected_in_a_known_binary():
    """kernel32 exports the file APIs; a binary importing from it should show
    file_api_count > 0. This pins the API grouping to something checkable."""
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    target = system32 / "notepad.exe"
    if not target.exists() or not is_pe(str(target)):
        pytest.skip("notepad.exe not available")

    features = extract_pe_features(str(target))
    assert features["pe_file_api_count"] > 0, "notepad imports no file APIs, which cannot be right"
    names = suspicious_api_names(str(target))
    assert names, "no behavioural API names surfaced for notepad.exe"
    assert all(isinstance(name, str) for name in names)


# ------------------------------------------------------------- non-PE input


def test_a_non_pe_file_yields_zeros_not_an_error(tmp_path):
    document = tmp_path / "report.docx"
    document.write_bytes(os.urandom(50000))

    features = extract_pe_features(str(document))
    assert features["is_pe"] == 0
    assert features["pe_imports_count"] == 0
    assert set(features) == set(empty_pe_features())
    assert suspicious_api_names(str(document)) == []


def test_a_truncated_pe_does_not_raise(tmp_path):
    """A hostile or half-written file must not take the Monitor's event thread
    down - this runs inline on every file event."""
    stub = tmp_path / "truncated.exe"
    stub.write_bytes(b"MZ" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 10)

    features = extract_pe_features(str(stub))
    assert set(features) == set(empty_pe_features())
    assert suspicious_api_names(str(stub)) == []


def test_a_missing_file_yields_zeros(tmp_path):
    assert extract_pe_features(str(tmp_path / "nope.exe"))["is_pe"] == 0
    assert is_pe(str(tmp_path / "nope.exe")) is False


def test_an_mz_header_alone_is_not_a_pe(tmp_path):
    """DOS executables start MZ but have no PE header. Misreporting them would
    put garbage in the header columns."""
    dos = tmp_path / "old.com"
    dos.write_bytes(b"MZ" + os.urandom(1000))
    assert is_pe(str(dos)) is False
    assert extract_pe_features(str(dos))["is_pe"] == 0


# ------------------------------------------- the /features contract (spec 3.4.2)


# Every field gateway.yaml marks required on FeatureSet, which is also the shape
# spec 3.4.2 shows going into /predict.
FEATURESET_REQUIRED = [
    "shannon_entropy",
    "file_size",
    "magic_bytes",
    "modification_rate",
    "pe_imports_count",
    "api_calls",
]


def test_features_endpoint_satisfies_the_documented_featureset(tmp_path):
    """pe_imports_count and api_calls are required by the contract and were
    absent from the payload entirely until the PE parser existed - so /analyze
    was shipping an incomplete FeatureSet to the ML engine."""
    import app as monitor_app

    document = tmp_path / "report.docx"
    document.write_bytes(os.urandom(40000))

    features = monitor_app.extract_features(str(document))
    missing = [field for field in FEATURESET_REQUIRED if field not in features]
    assert not missing, f"FeatureSet fields missing from /features: {missing}"

    assert features["pe_imports_count"] == 0, "a .docx cannot have PE imports"
    assert features["api_calls"] == []


@needs_pe
def test_the_featureset_carries_real_pe_values_for_an_executable():
    import app as monitor_app

    with_imports = next(
        (p for p in REAL_PES if extract_pe_features(str(p))["pe_imports_count"] > 0), None
    )
    if with_imports is None:
        pytest.skip("no PE with imports available")

    features = monitor_app.extract_features(str(with_imports))
    assert features["pe_imports_count"] > 0
    assert isinstance(features["api_calls"], list)
