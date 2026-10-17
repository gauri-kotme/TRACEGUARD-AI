"""
Tests for traceguard.database
"""

import tempfile
from pathlib import Path
import pytest
from traceguard.database import (
    init_db,
    register_baseline,
    get_baseline_by_identifier,
    get_baseline_by_hash,
    update_baseline,
    list_baselines,
    record_scan,
    get_scans,
    get_scan_stats,
    clear_history
)


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    init_db(db_path)
    yield db_path
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass


def test_baseline_lifecycle(temp_db):
    ident = "critical_system_file.dll"
    h1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h2 = "aaaaaaaa98fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Register
    b_id = register_baseline(
        identifier=ident,
        file_name="critical_system_file.dll",
        sha256_hash=h1,
        file_size=4096,
        file_type="binary",
        entropy=6.1,
        trusted_notes="Initial gold master release",
        db_path=temp_db
    )
    assert b_id > 0

    # Retrieve by identifier & hash
    rec = get_baseline_by_identifier(ident, db_path=temp_db)
    assert rec is not None
    assert rec["sha256_hash"] == h1

    rec_by_h = get_baseline_by_hash(h1, db_path=temp_db)
    assert rec_by_h is not None
    assert rec_by_h["identifier"] == ident

    # Prevent duplicate identifier registration
    with pytest.raises(ValueError):
        register_baseline(
            identifier=ident,
            file_name="duplicate.dll",
            sha256_hash=h1,
            file_size=4096,
            db_path=temp_db
        )

    # Update baseline explicitly
    updated = update_baseline(
        baseline_id=b_id,
        new_sha256_hash=h2,
        new_file_size=5120,
        notes_append="Official patch v2.0",
        db_path=temp_db
    )
    assert updated is True

    rec_updated = get_baseline_by_identifier(ident, db_path=temp_db)
    assert rec_updated["sha256_hash"] == h2
    assert "Official patch v2.0" in rec_updated["trusted_notes"]


def test_scans_and_stats(temp_db):
    # Record scan
    s_id = record_scan(
        file_name="suspicious.exe",
        sha256_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        file_size=10240,
        risk_score=75,
        risk_level="HIGH",
        integrity_status="CHANGED",
        db_path=temp_db
    )
    assert s_id > 0

    scans, total = get_scans(db_path=temp_db)
    assert total == 1
    assert scans[0]["file_name"] == "suspicious.exe"

    stats = get_scan_stats(db_path=temp_db)
    assert stats["total_scans"] == 1
    assert stats["changed_count"] == 1
    assert stats["investigation_required"] == 1

    # Clear history
    clear_history(db_path=temp_db)
    scans_after, total_after = get_scans(db_path=temp_db)
    assert total_after == 0
