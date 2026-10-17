"""
TRACEGUARD AI - Hasher & Cryptographic Utilities
Computes SHA-256, SHA-1, MD5, Shannon Entropy, and provides visual hash diffing.
Never executes or persists complete file contents.
"""

import hmac
import math
import hashlib
from typing import Dict, Any, Union, BinaryIO, Tuple
from pathlib import Path
from traceguard.config import HASH_CHUNK_SIZE


def compute_hashes(source: Union[str, Path, bytes, BinaryIO], chunk_size: int = HASH_CHUNK_SIZE) -> Dict[str, Any]:
    """
    Computes cryptographic hashes (SHA-256, SHA-1, MD5) for a file path,
    stream, or raw bytes using chunked streaming to prevent high memory usage.

    Returns:
        dict: {
            "sha256": hex string,
            "sha1": hex string,
            "md5": hex string,
            "size_bytes": total integer bytes read
        }
    """
    h_sha256 = hashlib.sha256()
    h_sha1 = hashlib.sha1()
    h_md5 = hashlib.md5()
    total_bytes = 0

    if isinstance(source, (str, Path)):
        p = Path(source)
        if not p.is_file():
            raise FileNotFoundError(f"File not found: {p}")
        with open(p, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                h_sha256.update(chunk)
                h_sha1.update(chunk)
                h_md5.update(chunk)
    elif isinstance(source, bytes):
        total_bytes = len(source)
        h_sha256.update(source)
        h_sha1.update(source)
        h_md5.update(source)
    else:
        # File-like object (e.g. Streamlit UploadedFile or BytesIO)
        # Store current position if seekable
        seekable = hasattr(source, "seek") and hasattr(source, "tell")
        orig_pos = source.tell() if seekable else 0
        if seekable:
            source.seek(0)

        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            h_sha256.update(chunk)
            h_sha1.update(chunk)
            h_md5.update(chunk)

        # Reset pointer back to original position
        if seekable:
            source.seek(orig_pos)

    return {
        "sha256": h_sha256.hexdigest().lower(),
        "sha1": h_sha1.hexdigest().lower(),
        "md5": h_md5.hexdigest().lower(),
        "size_bytes": total_bytes
    }


def calculate_entropy(data: bytes) -> Tuple[float, str]:
    """
    Calculates Shannon Entropy (0.0 to 8.0) of a byte sample.
    Returns (entropy_value, interpretation_string).
    """
    if not data:
        return 0.0, "Zero entropy (empty content)"

    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1

    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    entropy = round(entropy, 4)

    # Human-readable interpretation
    if entropy < 1.0:
        interp = "Uniform / highly repetitive byte sequence"
    elif entropy < 4.0:
        interp = "Low randomness (typical plain text or simple config)"
    elif entropy < 6.5:
        interp = "Moderate randomness (standard code, binary structures, uncompressed docs)"
    elif entropy < 7.2:
        interp = "High density data (dense binary code or light compression)"
    else:
        interp = "Very high randomness (indicates packed payload, strong compression, or encryption)"

    return entropy, interp


def compare_hashes(hash_a: str, hash_b: str) -> Dict[str, Any]:
    """
    Compares two hashes using constant-time comparison and returns detailed diff metadata.
    """
    a = (hash_a or "").strip().lower()
    b = (hash_b or "").strip().lower()

    if not a or not b:
        return {
            "match": False,
            "status": "UNKNOWN",
            "identical_chars": 0,
            "diff_chars": max(len(a), len(b)),
            "similarity_percent": 0.0
        }

    is_match = hmac.compare_digest(a, b)

    # Compute character-by-character alignment
    max_len = max(len(a), len(b))
    matches = 0
    diff_indices = []

    for i in range(max_len):
        char_a = a[i] if i < len(a) else None
        char_b = b[i] if i < len(b) else None
        if char_a == char_b:
            matches += 1
        else:
            diff_indices.append(i)

    similarity = round((matches / max_len) * 100, 2) if max_len > 0 else 0.0

    return {
        "match": is_match,
        "status": "UNCHANGED" if is_match else "CHANGED",
        "identical_chars": matches,
        "diff_chars": len(diff_indices),
        "diff_indices": diff_indices,
        "similarity_percent": similarity
    }
