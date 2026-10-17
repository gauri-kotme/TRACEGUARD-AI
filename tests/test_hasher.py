"""
Tests for traceguard.hasher
"""

import io
import hashlib
from traceguard.hasher import compute_hashes, calculate_entropy, compare_hashes


def test_compute_hashes_known_data():
    data = b"TRACEGUARD AI - Verify. Investigate. Trust."
    expected_sha256 = hashlib.sha256(data).hexdigest().lower()
    expected_sha1 = hashlib.sha1(data).hexdigest().lower()
    expected_md5 = hashlib.md5(data).hexdigest().lower()

    res = compute_hashes(data)
    assert res["sha256"] == expected_sha256
    assert res["sha1"] == expected_sha1
    assert res["md5"] == expected_md5
    assert res["size_bytes"] == len(data)


def test_compute_hashes_stream():
    data = b"Testing stream hashing with BytesIO"
    stream = io.BytesIO(data)
    res = compute_hashes(stream)
    assert res["sha256"] == hashlib.sha256(data).hexdigest().lower()
    # Stream should be rewound to original pos
    assert stream.tell() == 0


def test_calculate_entropy():
    # Empty data -> 0.0
    val_empty, _ = calculate_entropy(b"")
    assert val_empty == 0.0

    # Uniform repetitive byte -> 0.0
    val_uniform, _ = calculate_entropy(b"A" * 1000)
    assert val_uniform == 0.0

    # High entropy random-like byte sequence
    high_rand = bytes(list(range(256)) * 4)
    val_high, interp = calculate_entropy(high_rand)
    assert val_high > 7.5
    assert "randomness" in interp.lower() or "density" in interp.lower()


def test_compare_hashes():
    h1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h3 = "ffffc44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    match_res = compare_hashes(h1, h2)
    assert match_res["match"] is True
    assert match_res["status"] == "UNCHANGED"
    assert match_res["similarity_percent"] == 100.0

    diff_res = compare_hashes(h1, h3)
    assert diff_res["match"] is False
    assert diff_res["status"] == "CHANGED"
    assert diff_res["similarity_percent"] < 100.0
