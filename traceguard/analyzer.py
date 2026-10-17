"""
TRACEGUARD AI - File Analyzer
Extracts cryptographic fingerprints, header magic signatures, MIME types,
filename anomalies, and structural characteristics without ever executing files.
"""

import datetime
import mimetypes
from pathlib import Path
from typing import Dict, Any, Union, BinaryIO, Optional
from traceguard.config import (
    MAGIC_SIGNATURES,
    SAMPLE_ANALYSIS_SIZE,
    UNICODE_SPOOF_CHARS,
)
from traceguard.hasher import compute_hashes, calculate_entropy


def format_bytes(size: int) -> str:
    """Formats byte counts into human-readable strings (e.g., 2.45 MB)."""
    if size < 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024.0
    return f"{size:.2f} PB"


def extract_header_bytes(source: Union[str, Path, bytes, BinaryIO], num_bytes: int = 512) -> bytes:
    """
    Safely reads the initial bytes of a file or stream without reading the whole file.
    Never executes any code.
    """
    if isinstance(source, (str, Path)):
        p = Path(source)
        if not p.is_file():
            return b""
        with open(p, "rb") as f:
            return f.read(num_bytes)
    elif isinstance(source, bytes):
        return source[:num_bytes]
    else:
        # Seekable file-like stream
        seekable = hasattr(source, "seek") and hasattr(source, "tell")
        orig_pos = source.tell() if seekable else 0
        if seekable:
            source.seek(0)
        data = source.read(num_bytes)
        if seekable:
            source.seek(orig_pos)
        return data


def format_hex_dump(data: bytes, max_bytes: int = 32) -> Dict[str, str]:
    """Generates formatted hex and ASCII representations of header bytes."""
    sample = data[:max_bytes]
    hex_list = [f"{b:02X}" for b in sample]
    hex_spaced = " ".join(hex_list)

    # ASCII representation: readable if printable ASCII, else '.'
    ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in sample]
    ascii_str = "".join(ascii_chars)

    return {
        "hex": hex_spaced,
        "ascii": ascii_str,
        "raw_length": len(sample)
    }


def identify_magic_signature(header: bytes) -> Optional[Dict[str, Any]]:
    """
    Matches the file header against known file magic signatures.
    Returns the matching signature dictionary or None.
    """
    if not header:
        return None

    for sig in MAGIC_SIGNATURES:
        magic = sig["magic"]
        offset = sig["offset"]
        if len(header) >= offset + len(magic):
            if header[offset:offset + len(magic)] == magic:
                return {
                    "id": sig["id"],
                    "name": sig["name"],
                    "category": sig["category"],
                    "mime": sig["mime"],
                    "expected_extensions": sig["extensions"]
                }
    return None


def inspect_filename_anomalies(filename: str) -> Dict[str, Any]:
    """
    Checks for filename spoofing techniques including:
    - Multiple / double extensions (e.g., test.pdf.exe)
    - Unicode Bidirectional / RTLO spoofing characters
    - Trailing spaces or hidden dots
    """
    clean_name = filename.strip()
    p = Path(clean_name)

    # Split all extensions: 'archive.tar.gz' -> ['.tar', '.gz']
    suffixes = [s.lower() for s in p.suffixes]
    ext = p.suffix.lower() if p.suffix else ""

    # Check for Unicode Spoof Characters
    found_spoof_chars = []
    for char, name in UNICODE_SPOOF_CHARS.items():
        if char in filename:
            found_spoof_chars.append({"char_code": hex(ord(char)), "name": name})

    # Trailing spaces or periods (Windows filter evasion technique)
    has_trailing_space = filename.endswith(" ")
    has_trailing_dot = filename.endswith(".") and not filename.startswith(".")

    return {
        "filename": filename,
        "clean_name": clean_name,
        "primary_extension": ext,
        "all_suffixes": suffixes,
        "suffix_count": len(suffixes),
        "is_double_extension": len(suffixes) >= 2,
        "has_spoof_chars": len(found_spoof_chars) > 0,
        "spoof_chars": found_spoof_chars,
        "has_trailing_space": has_trailing_space,
        "has_trailing_dot": has_trailing_dot,
        "is_hidden": clean_name.startswith(".") and len(clean_name) > 1,
    }


def analyze_file(source: Union[str, Path, BinaryIO], filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs full non-invasive analysis of a file:
    - Calculates SHA-256, SHA-1, MD5
    - Calculates Shannon Entropy of sample
    - Extracts header magic bytes
    - Identifies MIME types from standard catalog & header
    - Inspects filename anomalies
    """
    # Resolve filename
    if filename is None:
        if isinstance(source, (str, Path)):
            filename = Path(source).name
        elif hasattr(source, "name"):
            filename = str(source.name)
        else:
            filename = "unnamed_sample.bin"

    # Compute hashes & total size safely
    hash_data = compute_hashes(source)
    size_bytes = hash_data["size_bytes"]

    # Extract header sample for magic & entropy
    header_sample = extract_header_bytes(source, num_bytes=SAMPLE_ANALYSIS_SIZE)
    header_dump = format_hex_dump(header_sample, max_bytes=32)

    # Shannon Entropy
    entropy_val, entropy_interp = calculate_entropy(header_sample)

    # Magic Signature
    signature = identify_magic_signature(header_sample)

    # Filename anomalies
    fn_anomalies = inspect_filename_anomalies(filename)

    # Mimetype guess via standard Python library
    mime_type, mime_encoding = mimetypes.guess_type(filename)
    if mime_type is None and signature:
        mime_type = signature["mime"]

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        "file_name": filename,
        "file_size": size_bytes,
        "file_size_formatted": format_bytes(size_bytes),
        "sha256": hash_data["sha256"],
        "sha1": hash_data["sha1"],
        "md5": hash_data["md5"],
        "primary_extension": fn_anomalies["primary_extension"],
        "all_suffixes": fn_anomalies["all_suffixes"],
        "mime_type": mime_type or "application/octet-stream",
        "mime_encoding": mime_encoding,
        "entropy": entropy_val,
        "entropy_interpretation": entropy_interp,
        "header_hex": header_dump["hex"],
        "header_ascii": header_dump["ascii"],
        "header_length": header_dump["raw_length"],
        "detected_signature": signature,
        "filename_anomalies": fn_anomalies,
        "timestamp": now_iso
    }
