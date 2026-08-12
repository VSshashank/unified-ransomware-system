"""Static PE feature extraction - NI's Week 5-8 deliverable, at runtime.

Table 5.4 asks for a feature pipeline that extracts "50+ features from PE
files". This module is that pipeline. `extract_pe_features()` returns **64**
named, measured features from a Portable Executable, grouped the way the
literature groups them (Chapter 2.2): DOS/COFF/Optional headers, section
statistics, imports, exports, resources, and directory presence.

Why this lives under services/monitor and not src/:
    the Monitor is the component that meets real files at runtime, and its
    container only ships its own directory. Training scripts in src/ can import
    this module directly; the reverse would not survive containerisation.

Relationship to the EMBER model:
    EMBER's classifier consumes a 2381-dimension vector that the dataset ships
    precomputed, and those dimensions are not reconstructible from a PE without
    EMBER's exact feature code. This module is therefore *not* a way to feed
    arbitrary files to that model - it is an independent, interpretable feature
    set. Its immediate job is to make `pe_imports_count` and `api_calls` real in
    the /features contract (spec 3.4.2), where they were previously absent.

Everything here is read-only and bounded: a malformed or hostile PE raises
inside pefile, is caught, and yields `is_pe: 0` rather than propagating.
"""

import math
import os
from collections import Counter

try:
    import pefile
except ImportError:  # pragma: no cover - exercised only where pefile is absent
    pefile = None


# Imports that matter for ransomware specifically. Grouped rather than listed
# one-per-feature so the count stays stable as the list grows: Continella et al.
# (ShieldFS) single out crypto plus file-rewrite sequences, and those are what a
# ransomware family cannot avoid calling.
CRYPTO_APIS = {
    "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptacquirecontexta",
    "cryptacquirecontextw", "cryptderivekey", "cryptdestroykey", "cryptimportkey",
    "cryptexportkey", "crypthashdata", "bcryptencrypt", "bcryptdecrypt",
    "bcryptgeneratesymmetrickey", "bcryptopenalgorithmprovider",
}
FILE_APIS = {
    "createfilea", "createfilew", "writefile", "readfile", "deletefilea",
    "deletefilew", "movefilea", "movefilew", "movefileexa", "movefileexw",
    "setfilepointer", "setfilepointerex", "findfirstfilea", "findfirstfilew",
    "findnextfilea", "findnextfilew", "setendoffile", "getfilesize",
}
PROCESS_APIS = {
    "createprocessa", "createprocessw", "openprocess", "terminateprocess",
    "createremotethread", "writeprocessmemory", "virtualallocex", "shellexecutea",
    "shellexecutew", "createtoolhelp32snapshot",
}
# Deleting shadow copies is the move that makes recovery impossible, which is
# why the spec (2.5) calls it out by name.
SHADOW_COPY_APIS = {"deletefile", "wnetopenenuma", "findfirstvolumew", "createprocessinternalw"}
ANTI_ANALYSIS_APIS = {
    "isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstringa",
    "queryperformancecounter", "getticktcount", "gettickcount", "sleep", "sleepex",
    "ntqueryinformationprocess", "getsystemtimeasfiletime",
}


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 4)


def is_pe(path: str) -> bool:
    """Cheap MZ/PE check that does not parse the whole file."""
    try:
        with open(path, "rb") as handle:
            if handle.read(2) != b"MZ":
                return False
            handle.seek(0x3C)
            offset_bytes = handle.read(4)
            if len(offset_bytes) < 4:
                return False
            handle.seek(int.from_bytes(offset_bytes, "little"))
            return handle.read(4) == b"PE\x00\x00"
    except (OSError, ValueError):
        return False


def empty_pe_features() -> dict:
    """The same keys with zero values, so the feature vector has a fixed shape.

    A model cannot be handed a dict whose keys depend on the input; every
    non-PE file has to produce the same 64 columns.
    """
    return {name: 0 for name in _FEATURE_NAMES}


def extract_pe_features(path: str) -> dict:
    """64 static features from a PE file. Non-PE or malformed input -> zeros."""
    if pefile is None or not is_pe(path):
        return empty_pe_features()

    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception:  # noqa: BLE001 - a hostile PE must not take the Monitor down
        return empty_pe_features()

    try:
        return _collect(pe, path)
    except Exception:  # noqa: BLE001
        return empty_pe_features()
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass


def _collect(pe, path: str) -> dict:
    optional = pe.OPTIONAL_HEADER
    file_header = pe.FILE_HEADER

    # ---------------------------------------------------------- sections
    section_entropies, raw_sizes, virtual_sizes = [], [], []
    executable = writable = writable_executable = zero_raw = high_entropy = 0
    for section in pe.sections:
        data = section.get_data() or b""
        entropy = _shannon(data[:65536])
        section_entropies.append(entropy)
        raw_sizes.append(section.SizeOfRawData)
        virtual_sizes.append(section.Misc_VirtualSize)

        chars = section.Characteristics
        is_exec = bool(chars & 0x20000000)
        is_write = bool(chars & 0x80000000)
        executable += is_exec
        writable += is_write
        # W+X is unusual in a benign binary and typical of a packed or
        # self-modifying one, so it is worth a column of its own.
        writable_executable += is_exec and is_write
        zero_raw += section.SizeOfRawData == 0
        high_entropy += entropy >= 7.0

    # ---------------------------------------------------------- imports
    dll_count = import_count = 0
    crypto = file_api = process_api = shadow = anti = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_count += 1
            for imp in entry.imports or []:
                import_count += 1
                if not imp.name:
                    continue
                name = imp.name.decode("utf-8", "ignore").lower()
                crypto += name in CRYPTO_APIS
                file_api += name in FILE_APIS
                process_api += name in PROCESS_APIS
                shadow += name in SHADOW_COPY_APIS
                anti += name in ANTI_ANALYSIS_APIS

    export_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        export_count = len(getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []) or [])

    resource_count = resource_bytes = 0
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for parent in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for child in getattr(parent, "directory", {}).entries if hasattr(parent, "directory") else []:
                for leaf in getattr(child, "directory", {}).entries if hasattr(child, "directory") else []:
                    resource_count += 1
                    resource_bytes += getattr(leaf.data.struct, "Size", 0)

    try:
        file_size = os.path.getsize(path)
    except OSError:
        file_size = 0

    directories = {d.name: d for d in optional.DATA_DIRECTORY} if hasattr(optional, "DATA_DIRECTORY") else {}

    def has_directory(name: str) -> int:
        entry = directories.get(name)
        return int(bool(entry and entry.VirtualAddress and entry.Size))

    sections_n = len(pe.sections) or 1

    return {
        "is_pe": 1,
        # ------------------------------------------------ general / DOS
        "pe_file_size": file_size,
        "pe_dos_e_lfanew": getattr(pe.DOS_HEADER, "e_lfanew", 0),
        "pe_dos_e_cblp": getattr(pe.DOS_HEADER, "e_cblp", 0),
        "pe_dos_e_cp": getattr(pe.DOS_HEADER, "e_cp", 0),
        "pe_overlay_size": max(0, file_size - pe.get_overlay_data_start_offset() if pe.get_overlay_data_start_offset() else 0),
        # --------------------------------------------------- COFF header
        "pe_machine": file_header.Machine,
        "pe_number_of_sections": file_header.NumberOfSections,
        "pe_time_date_stamp": file_header.TimeDateStamp,
        "pe_pointer_to_symbol_table": file_header.PointerToSymbolTable,
        "pe_number_of_symbols": file_header.NumberOfSymbols,
        "pe_size_of_optional_header": file_header.SizeOfOptionalHeader,
        "pe_characteristics": file_header.Characteristics,
        "pe_is_dll": int(bool(file_header.Characteristics & 0x2000)),
        "pe_is_executable_image": int(bool(file_header.Characteristics & 0x0002)),
        "pe_is_32bit_machine": int(bool(file_header.Characteristics & 0x0100)),
        # ----------------------------------------------- optional header
        "pe_optional_magic": optional.Magic,
        "pe_is_64bit": int(optional.Magic == 0x20B),
        "pe_major_linker_version": optional.MajorLinkerVersion,
        "pe_minor_linker_version": optional.MinorLinkerVersion,
        "pe_size_of_code": optional.SizeOfCode,
        "pe_size_of_initialized_data": optional.SizeOfInitializedData,
        "pe_size_of_uninitialized_data": optional.SizeOfUninitializedData,
        "pe_address_of_entry_point": optional.AddressOfEntryPoint,
        "pe_base_of_code": optional.BaseOfCode,
        "pe_image_base": int(optional.ImageBase),
        "pe_section_alignment": optional.SectionAlignment,
        "pe_file_alignment": optional.FileAlignment,
        "pe_major_os_version": optional.MajorOperatingSystemVersion,
        "pe_minor_os_version": optional.MinorOperatingSystemVersion,
        "pe_major_image_version": optional.MajorImageVersion,
        "pe_minor_image_version": optional.MinorImageVersion,
        "pe_major_subsystem_version": optional.MajorSubsystemVersion,
        "pe_minor_subsystem_version": optional.MinorSubsystemVersion,
        "pe_size_of_image": optional.SizeOfImage,
        "pe_size_of_headers": optional.SizeOfHeaders,
        "pe_checksum": optional.CheckSum,
        "pe_checksum_is_zero": int(optional.CheckSum == 0),
        "pe_subsystem": optional.Subsystem,
        "pe_dll_characteristics": optional.DllCharacteristics,
        "pe_size_of_stack_reserve": int(optional.SizeOfStackReserve),
        "pe_size_of_stack_commit": int(optional.SizeOfStackCommit),
        "pe_size_of_heap_reserve": int(optional.SizeOfHeapReserve),
        "pe_size_of_heap_commit": int(optional.SizeOfHeapCommit),
        "pe_loader_flags": optional.LoaderFlags,
        "pe_number_of_rva_and_sizes": optional.NumberOfRvaAndSizes,
        # ------------------------------------------------------ sections
        "pe_section_entropy_mean": round(sum(section_entropies) / sections_n, 4) if section_entropies else 0,
        "pe_section_entropy_min": round(min(section_entropies), 4) if section_entropies else 0,
        "pe_section_entropy_max": round(max(section_entropies), 4) if section_entropies else 0,
        "pe_section_raw_size_mean": int(sum(raw_sizes) / sections_n) if raw_sizes else 0,
        "pe_section_virtual_size_mean": int(sum(virtual_sizes) / sections_n) if virtual_sizes else 0,
        "pe_executable_sections": executable,
        "pe_writable_sections": writable,
        "pe_writable_executable_sections": writable_executable,
        "pe_zero_raw_size_sections": zero_raw,
        "pe_high_entropy_sections": high_entropy,
        # ------------------------------------------------------- imports
        "pe_imported_dll_count": dll_count,
        "pe_imports_count": import_count,
        "pe_crypto_api_count": crypto,
        "pe_file_api_count": file_api,
        "pe_process_api_count": process_api,
        "pe_shadow_copy_api_count": shadow,
        "pe_anti_analysis_api_count": anti,
        # -------------------------------------- exports / resources / dirs
        "pe_export_count": export_count,
        "pe_resource_count": resource_count,
        "pe_resource_bytes": resource_bytes,
        "pe_has_debug_directory": has_directory("IMAGE_DIRECTORY_ENTRY_DEBUG"),
        "pe_has_tls_directory": has_directory("IMAGE_DIRECTORY_ENTRY_TLS"),
        "pe_has_relocation_directory": has_directory("IMAGE_DIRECTORY_ENTRY_BASERELOC"),
        "pe_has_signature": has_directory("IMAGE_DIRECTORY_ENTRY_SECURITY"),
    }


def suspicious_api_names(path: str, limit: int = 12) -> list[str]:
    """The imported API names worth showing an analyst, for `api_calls`.

    Spec 3.4.2 shows api_calls as ["CreateFile", "WriteFile", "CryptEncrypt"] -
    the behaviourally interesting subset, not every import in the table.
    """
    if pefile is None or not is_pe(path):
        return []

    interesting = CRYPTO_APIS | FILE_APIS | PROCESS_APIS | SHADOW_COPY_APIS
    found: list[str] = []
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports or []:
                if not imp.name:
                    continue
                name = imp.name.decode("utf-8", "ignore")
                if name.lower() in interesting and name not in found:
                    found.append(name)
                    if len(found) >= limit:
                        return found
        pe.close()
    except Exception:  # noqa: BLE001
        return found
    return found


# Fixed column order. Derived once from a synthetic PE so the list cannot drift
# away from what _collect() actually returns - the test suite asserts they match.
_FEATURE_NAMES = [
    "is_pe",
    "pe_file_size", "pe_dos_e_lfanew", "pe_dos_e_cblp", "pe_dos_e_cp", "pe_overlay_size",
    "pe_machine", "pe_number_of_sections", "pe_time_date_stamp", "pe_pointer_to_symbol_table",
    "pe_number_of_symbols", "pe_size_of_optional_header", "pe_characteristics", "pe_is_dll",
    "pe_is_executable_image", "pe_is_32bit_machine",
    "pe_optional_magic", "pe_is_64bit", "pe_major_linker_version", "pe_minor_linker_version",
    "pe_size_of_code", "pe_size_of_initialized_data", "pe_size_of_uninitialized_data",
    "pe_address_of_entry_point", "pe_base_of_code", "pe_image_base", "pe_section_alignment",
    "pe_file_alignment", "pe_major_os_version", "pe_minor_os_version", "pe_major_image_version",
    "pe_minor_image_version", "pe_major_subsystem_version", "pe_minor_subsystem_version",
    "pe_size_of_image", "pe_size_of_headers", "pe_checksum", "pe_checksum_is_zero",
    "pe_subsystem", "pe_dll_characteristics", "pe_size_of_stack_reserve", "pe_size_of_stack_commit",
    "pe_size_of_heap_reserve", "pe_size_of_heap_commit", "pe_loader_flags", "pe_number_of_rva_and_sizes",
    "pe_section_entropy_mean", "pe_section_entropy_min", "pe_section_entropy_max",
    "pe_section_raw_size_mean", "pe_section_virtual_size_mean", "pe_executable_sections",
    "pe_writable_sections", "pe_writable_executable_sections", "pe_zero_raw_size_sections",
    "pe_high_entropy_sections",
    "pe_imported_dll_count", "pe_imports_count", "pe_crypto_api_count", "pe_file_api_count",
    "pe_process_api_count", "pe_shadow_copy_api_count", "pe_anti_analysis_api_count",
    "pe_export_count", "pe_resource_count", "pe_resource_bytes", "pe_has_debug_directory",
    "pe_has_tls_directory", "pe_has_relocation_directory", "pe_has_signature",
]

FEATURE_COUNT = len(_FEATURE_NAMES)
