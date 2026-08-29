"""
Shared pytest fixtures for the signature-analysis test suite.

Builds small, synthetic, benign fixtures on the fly so tests never depend
on real malware samples or large binary files being committed to the repo.
"""

import os
import struct
import sys

import pytest

# Make the malware_analyzer package importable regardless of cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


def build_minimal_pe(section_data: bytes = b"\x90" * 256, extra_strings: bytes = b"") -> bytes:
    """
    Builds a small, syntactically-valid 32-bit PE (MZ + PE + optional header
    + one .text section) purely from struct-packed bytes, with no external
    dependency, so pefile/yara can parse it without needing a real compiled
    binary. This is a benign synthetic fixture, not functional/executable
    malware or shellcode.
    """
    # --- DOS header (64 bytes total, offset-addressed to avoid ambiguity) ---
    e_lfanew = 0x80
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"                              # e_magic
    struct.pack_into("<H", dos_header, 2, 0x90)           # e_cblp
    struct.pack_into("<H", dos_header, 4, 0x03)           # e_cp
    struct.pack_into("<H", dos_header, 8, 4)              # e_cparhdr
    struct.pack_into("<H", dos_header, 10, 0xFFFF)        # e_minalloc
    struct.pack_into("<H", dos_header, 14, 0xB8)          # e_ss
    struct.pack_into("<H", dos_header, 20, 0x40)          # e_ip
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)    # e_lfanew
    dos_header = bytes(dos_header)
    # Pad with a DOS stub so the PE header starts exactly at e_lfanew.
    dos_header = dos_header.ljust(e_lfanew, b"\x00")

    # --- PE / COFF file header ---
    machine = 0x014C  # IMAGE_FILE_MACHINE_I386
    num_sections = 1
    timestamp = 0x5F000000
    opt_header_size = 224  # standard 32-bit optional header size
    characteristics = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE

    coff_header = struct.pack(
        "<4s HH I I I HH",
        b"PE\x00\x00", machine, num_sections, timestamp, 0, 0,
        opt_header_size, characteristics,
    )

    # --- Optional header (32-bit, PE32) ---
    section_va = 0x1000
    section_raw_offset = 0x200
    section_size_aligned = ((len(section_data) + 0x1FF) // 0x200) * 0x200
    image_size = section_va + section_size_aligned + 0x1000

    # 30 fields total for the PE32 optional header (before data directories):
    # H,B,B, I*9 (SizeOfCode..FileAlignment), H*6 (OS/Image/Subsys versions),
    # I*4 (Win32VersionValue,SizeOfImage,SizeOfHeaders,CheckSum), H*2 (Subsystem,
    # DllCharacteristics), I*6 (Stack/Heap reserve+commit, LoaderFlags, NumberOfRvaAndSizes)
    opt_header = struct.pack(
        "<HBB IIIIIIIII HHHHHH IIII HH IIIIII",
        0x10B, 6, 0,                              # Magic (PE32), linker ver major/minor
        len(section_data), 0, 0,                  # SizeOfCode, SizeOfInitData, SizeOfUninitData
        section_va,                                # AddressOfEntryPoint
        section_va,                                # BaseOfCode
        0,                                          # BaseOfData
        0x400000,                                   # ImageBase
        0x1000,                                      # SectionAlignment
        0x200,                                       # FileAlignment
        4, 0, 0, 0, 4, 0,                          # OS/Image/Subsystem version major/minor
        0, image_size, 0x400, 0,                    # Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum
        2, 0,                                        # Subsystem (WINDOWS_GUI), DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,  # Stack/Heap reserve+commit, LoaderFlags, NumberOfRvaAndSizes
    )
    assert len(opt_header) == opt_header_size - 16 * 8, len(opt_header)
    # Append 16 zeroed data directories (8 bytes each) as PE requires.
    data_directories = b"\x00" * (16 * 8)
    opt_header += data_directories

    # --- Section header (.text) ---
    section_name = b".text\x00\x00\x00"
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        section_name,
        len(section_data),        # VirtualSize
        section_va,                # VirtualAddress
        section_size_aligned,      # SizeOfRawData
        section_raw_offset,        # PointerToRawData
        0,                          # PointerToRelocations
        0,                          # PointerToLinenumbers
        0,                          # NumberOfRelocations
        0,                          # NumberOfLinenumbers
        0x60000020,                 # Characteristics: CODE | EXECUTE | READ
    )

    header = dos_header + coff_header + opt_header + section_header
    header = header.ljust(section_raw_offset, b"\x00")

    body = (section_data + extra_strings).ljust(section_size_aligned, b"\x00")

    return header + body


@pytest.fixture
def minimal_pe_bytes():
    return build_minimal_pe()


@pytest.fixture
def minimal_pe_path(tmp_path, minimal_pe_bytes):
    p = tmp_path / "synthetic_sample.exe"
    p.write_bytes(minimal_pe_bytes)
    return str(p)


@pytest.fixture
def keylogger_like_pe_path(tmp_path):
    """A synthetic PE whose .text section embeds strings matching the
    Suspicious_Keylogger_Combo YARA rule -- for a controlled positive test."""
    strings_blob = b"\x00".join(
        [b"SetWindowsHookExA", b"GetAsyncKeyState", b"ShowWindow", b""]
    )
    data = build_minimal_pe(section_data=b"\x90" * 64, extra_strings=strings_blob)
    p = tmp_path / "keylogger_like.exe"
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def benign_text_path(tmp_path):
    p = tmp_path / "benign.txt"
    p.write_text("Hello world, this is an ordinary benign text file.\n" * 20)
    return str(p)


@pytest.fixture
def empty_file_path(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    return str(p)


@pytest.fixture
def tiny_file_path(tmp_path):
    p = tmp_path / "tiny.bin"
    p.write_bytes(b"AB")
    return str(p)
