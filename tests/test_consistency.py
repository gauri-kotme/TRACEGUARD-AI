"""
Automated tests for TRACEGUARD AI:
1. Verdict and risk-level consistency
2. A normal PDF with high entropy
3. A suspicious file with multiple independent warning signs
4. A file with insufficient evidence
5. Risk score wording (never claims malware probability)
6. Trusted-file baseline and changed-file behavior
"""

import pytest
from traceguard.config import (
    VERDICT_LIKELY_SAFE,
    VERDICT_SUSPICIOUS,
    VERDICT_LIKELY_MALICIOUS,
    VERDICT_UNABLE_TO_DETERMINE,
    THEME_COLORS,
)
from traceguard.risk_engine import (
    evaluate_rules,
    calculate_risk_score,
    determine_verdict,
    determine_recommendation,
    RISK_LEVEL_DESCRIPTIONS,
)
from traceguard.database import (
    init_db,
    register_baseline,
    get_baseline_by_identifier,
    update_baseline,
)
from traceguard.hasher import compare_hashes


# ============================================================================
# 1. VERDICT AND RISK-LEVEL CONSISTENCY
# ============================================================================

def test_verdict_and_risk_level_consistency_across_score_bands():
    """
    Ensures that every part of the assessment agrees:
    - Verdict, risk level, color, summary, and headline must NEVER contradict.
    - Specifically, a score with warning signs (e.g. 25/100) must NEVER display
      'No important warning signs were detected'.
    """
    test_cases = [
        # (score, expected_level, expected_verdict, expected_color)
        (0, "SAFE", VERDICT_LIKELY_SAFE, THEME_COLORS["verdict_safe"]),
        (10, "LOW", VERDICT_LIKELY_SAFE, THEME_COLORS["verdict_safe"]),
        (25, "MEDIUM", VERDICT_SUSPICIOUS, THEME_COLORS["verdict_suspicious"]),
        (50, "MEDIUM", VERDICT_SUSPICIOUS, THEME_COLORS["verdict_suspicious"]),
        (75, "HIGH", VERDICT_LIKELY_MALICIOUS, THEME_COLORS["verdict_malicious"]),
        (95, "CRITICAL", VERDICT_LIKELY_MALICIOUS, THEME_COLORS["verdict_malicious"]),
    ]

    for score, exp_level, exp_verdict, exp_color in test_cases:
        mock_findings = []
        if score >= 75:
            mock_findings = [
                {"rule_id": "RULE-003", "name": "Disguised Executable", "severity": "CRITICAL", "points": 50, "evidence": "PE header", "simple_explanation": "Program disguised as document"},
                {"rule_id": "RULE-001", "name": "Double Extension", "severity": "HIGH", "points": 40, "evidence": ".pdf.exe", "simple_explanation": "Double extension"},
            ]
        elif score >= 20:
            mock_findings = [
                {"rule_id": "RULE-004", "name": "Header Mismatch", "severity": "MEDIUM", "points": 25, "evidence": "Mismatch", "simple_explanation": "Format mismatch"},
            ]
        elif score > 0:
            mock_findings = [
                {"rule_id": "RULE-005", "name": "Compressed Content", "severity": "LOW", "points": 5, "evidence": "Normal entropy", "simple_explanation": "Compressed content"},
            ]

        # 1. Check determine_verdict
        v_info = determine_verdict(
            risk_score=score,
            risk_level=exp_level,
            integrity_status="UNKNOWN",
            findings=mock_findings,
            file_size=5000,
            primary_ext=".pdf" if score < 75 else ".exe"
        )
        assert v_info["verdict"] == exp_verdict
        assert v_info["verdict_color"] == exp_color

        # 2. Check determine_recommendation
        rec = determine_recommendation(
            risk_score=score,
            risk_level=exp_level,
            integrity_status="UNKNOWN",
            findings=mock_findings,
            file_size=5000,
            primary_ext=".pdf" if score < 75 else ".exe"
        )
        assert rec["verdict"] == exp_verdict
        assert rec["verdict_color"] == exp_color

        # 3. Check consistency of messages: Score 25 must NEVER say 'No important warning signs'
        if score >= 20:
            assert "no important warning" not in rec["summary"].lower()
            assert "no significant warning" not in rec["summary"].lower()
            assert "review" in rec["summary"].lower() or "warning" in rec["summary"].lower() or "harmful" in rec["summary"].lower()
            level_desc = RISK_LEVEL_DESCRIPTIONS[exp_level]
            assert "no important warning" not in level_desc.lower()
            assert "no significant warning" not in level_desc.lower()
        else:
            assert "no significant warning" in rec["summary"].lower()


# ============================================================================
# 2. A NORMAL PDF WITH HIGH ENTROPY
# ============================================================================

def test_normal_pdf_with_high_entropy_not_malicious_or_alarming():
    """
    CRITICAL REQUIREMENT:
    A valid PDF with high entropy (e.g. 7.7) due to compressed streams/images
    must NOT be classified as malicious or produce an alarming verdict.
    Its impact must be lowered and explained in plain English.
    """
    analysis = {
        "file_name": "annual_financial_report.pdf",
        "primary_extension": ".pdf",
        "file_size": 150000,
        "entropy": 7.72,  # Naturally high entropy from compressed FlateDecode streams & embedded graphics
        "detected_signature": {
            "id": "PDF_DOC",
            "name": "Adobe Portable Document Format (PDF)",
            "mime": "application/pdf",
            "expected_extensions": [".pdf"],
            "category": "document"
        },
        "filename_anomalies": {
            "all_suffixes": [".pdf"],
            "suffix_count": 1,
            "has_spoof_chars": False,
            "has_trailing_space": False,
            "has_trailing_dot": False,
        }
    }

    findings = evaluate_rules(analysis)
    score_data = calculate_risk_score(findings)

    # Score must be low (< 20) because this is a legitimate compressed document format
    assert score_data["risk_score"] < 20
    assert score_data["risk_level"] in ["SAFE", "LOW"]

    rec = determine_recommendation(
        risk_score=score_data["risk_score"],
        risk_level=score_data["risk_level"],
        integrity_status="UNKNOWN",
        findings=findings,
        file_size=analysis["file_size"],
        primary_ext=analysis["primary_extension"]
    )

    # Must NOT produce an alarming or malicious verdict
    assert rec["verdict"] == VERDICT_LIKELY_SAFE
    assert rec["verdict"] != VERDICT_LIKELY_MALICIOUS
    assert rec["verdict"] != VERDICT_SUSPICIOUS

    # Check that explanation mentions compression is expected for this document
    f_entropy = next(f for f in findings if f["rule_id"] == "RULE-005")
    assert "compressed" in f_entropy["simple_explanation"].lower()
    assert "expected" in f_entropy["simple_explanation"].lower()


# ============================================================================
# 3. SUSPICIOUS FILE WITH MULTIPLE INDEPENDENT WARNING SIGNS
# ============================================================================

def test_suspicious_file_with_multiple_independent_warning_signs():
    """
    Ensures that a file combining multiple independent deception indicators
    (double extension .pdf.exe AND RTLO character AND executable payload)
    is properly flagged as High risk.
    """
    analysis = {
        "file_name": "Invoice_\u202Epdf.exe",
        "primary_extension": ".exe",
        "file_size": 45000,
        "entropy": 6.8,
        "detected_signature": {
            "id": "PE_EXE",
            "name": "Windows PE Executable / DLL",
            "mime": "application/x-dosexec",
            "expected_extensions": [".exe", ".dll"],
            "category": "executable"
        },
        "filename_anomalies": {
            "all_suffixes": [".pdf", ".exe"],
            "suffix_count": 2,
            "has_spoof_chars": True,
            "spoof_chars": [{"char": "\u202E", "name": "Right-to-Left Override [RLO]"}],
            "is_double_extension": True,
            "has_trailing_space": False,
            "has_trailing_dot": False,
        }
    }

    findings = evaluate_rules(analysis)
    rule_ids = {f["rule_id"] for f in findings}

    # Must trigger multiple independent rules
    assert "RULE-001" in rule_ids  # Double extension
    assert "RULE-002" in rule_ids  # RTLO spoofing

    score_data = calculate_risk_score(findings)
    assert score_data["risk_score"] >= 70
    assert score_data["risk_level"] in ["HIGH", "CRITICAL"]

    rec = determine_recommendation(
        risk_score=score_data["risk_score"],
        risk_level=score_data["risk_level"],
        integrity_status="UNKNOWN",
        findings=findings,
        file_size=analysis["file_size"],
        primary_ext=analysis["primary_extension"]
    )

    # Must be High risk / Likely Malicious
    assert rec["verdict"] == VERDICT_LIKELY_MALICIOUS
    assert "strong" in rec["summary"].lower() or "harmful" in rec["summary"].lower()


# ============================================================================
# 4. FILE WITH INSUFFICIENT EVIDENCE
# ============================================================================

def test_file_with_insufficient_evidence():
    """
    Ensures that empty (0 bytes) or corrupted files with missing headers
    produce 'Unable to determine' with clear, neutral explanation.
    """
    # Case A: 0-byte file
    analysis_empty = {
        "file_name": "lockfile.dat",
        "primary_extension": ".dat",
        "file_size": 0,
        "entropy": 0.0,
        "detected_signature": None,
        "filename_anomalies": {"all_suffixes": [".dat"], "suffix_count": 1, "has_spoof_chars": False}
    }
    findings_empty = evaluate_rules(analysis_empty)
    score_empty = calculate_risk_score(findings_empty)
    rec_empty = determine_recommendation(
        risk_score=score_empty["risk_score"],
        risk_level=score_empty["risk_level"],
        integrity_status="UNKNOWN",
        findings=findings_empty,
        file_size=0,
        primary_ext=".dat"
    )

    assert rec_empty["verdict"] == VERDICT_UNABLE_TO_DETERMINE
    assert "empty" in rec_empty["verdict_reason"].lower()
    assert rec_empty["badge_color"] == THEME_COLORS["verdict_undetermined"]

    # Case B: File with declared format but missing required header signature
    analysis_corrupt = {
        "file_name": "broken_document.pdf",
        "primary_extension": ".pdf",
        "file_size": 120,
        "entropy": 3.2,
        "detected_signature": None,  # Missing %PDF- magic bytes
        "filename_anomalies": {"all_suffixes": [".pdf"], "suffix_count": 1, "has_spoof_chars": False}
    }
    findings_corrupt = evaluate_rules(analysis_corrupt)
    score_corrupt = calculate_risk_score(findings_corrupt)
    rec_corrupt = determine_recommendation(
        risk_score=score_corrupt["risk_score"],
        risk_level=score_corrupt["risk_level"],
        integrity_status="UNKNOWN",
        findings=findings_corrupt,
        file_size=120,
        primary_ext=".pdf"
    )

    assert rec_corrupt["verdict"] == VERDICT_UNABLE_TO_DETERMINE


# ============================================================================
# 5. RISK SCORE WORDING (NEVER CLAIMS MALWARE PROBABILITY)
# ============================================================================

def test_risk_score_wording_never_claims_malware_probability():
    """
    Ensures that risk scores are explicitly explained as additive warning points,
    and NEVER as a probability of malware or percentage chance.
    Also ensures clean files never claim 100% guaranteed safety.
    """
    for score in [0, 5, 25, 50, 75, 100]:
        rec = determine_recommendation(
            risk_score=score,
            risk_level="MEDIUM" if score >= 20 else "SAFE",
            integrity_status="UNKNOWN",
            findings=[],
            file_size=1024,
            primary_ext=".pdf"
        )
        meaning = rec["score_meaning"]

        # Must explicitly disclaim percentage chance
        assert "NOT a percentage chance of malware" in meaning

        # Must NEVER state 'X% malware' or 'malware probability' as a fact
        assert f"{score}% malware" not in meaning.lower()

        # Clean file disclaimer must clarify no guarantee of absolute safety
        if score == 0:
            assert "not a guarantee" in rec["disclaimer"].lower() or "cannot guarantee" in rec["disclaimer"].lower()


# ============================================================================
# 6. TRUSTED-FILE BASELINE AND CHANGED-FILE BEHAVIOR
# ============================================================================

def test_trusted_file_baseline_and_changed_file_behavior(tmp_path):
    """
    Verifies full trusted-file baseline lifecycle:
    1. Register trusted baseline.
    2. Rescan unchanged file -> UNCHANGED.
    3. Rescan modified file -> CHANGED (alert).
    4. Baseline is NOT silently overwritten.
    5. Authorized update replaces baseline with explicit notes.
    """
    db_path = tmp_path / "test_baseline.db"
    init_db(db_path)

    initial_hash = "1111111111111111111111111111111111111111111111111111111111111111"
    modified_hash = "2222222222222222222222222222222222222222222222222222222222222222"
    file_identifier = "Quarterly_Budget.xlsx"

    # Step 1: Register baseline
    b_id = register_baseline(
        identifier=file_identifier,
        file_name="Quarterly_Budget.xlsx",
        sha256_hash=initial_hash,
        file_size=50000,
        trusted_notes="Finance approved v1.0",
        db_path=db_path
    )
    assert b_id > 0

    # Step 2: Unchanged verification
    baseline = get_baseline_by_identifier(file_identifier, db_path=db_path)
    assert baseline is not None
    diff_same = compare_hashes(initial_hash, baseline["sha256_hash"])
    assert diff_same["status"] == "UNCHANGED"
    assert diff_same["match"] is True

    # Step 3: Changed verification
    diff_changed = compare_hashes(modified_hash, baseline["sha256_hash"])
    assert diff_changed["status"] == "CHANGED"
    assert diff_changed["match"] is False

    # Step 4: Verify baseline was NOT silently modified
    baseline_check = get_baseline_by_identifier(file_identifier, db_path=db_path)
    assert baseline_check["sha256_hash"] == initial_hash

    # Step 5: Authorized update
    ok = update_baseline(
        baseline_id=b_id,
        new_sha256_hash=modified_hash,
        new_file_size=52000,
        new_entropy=7.1,
        notes_append="Finance approved Q2 revision",
        db_path=db_path
    )
    assert ok is True

    # Verify updated state
    baseline_updated = get_baseline_by_identifier(file_identifier, db_path=db_path)
    assert baseline_updated["sha256_hash"] == modified_hash
    assert "Q2 revision" in baseline_updated["trusted_notes"]


def test_modified_trusted_file_verdict_and_history_consistency(tmp_path):
    """
    Ensures that when a modified trusted file is scanned:
    1. Intrinsic content threat risk score remains 0 and risk_level remains 'SAFE'.
    2. Integrity status is 'CHANGED'.
    3. The overall verdict is escalated to 'Needs Review' with '⚠️ ALERT: File Has Changed'.
    4. Persisted scan history retains both the 'Needs Review' verdict and 'CHANGED' status.
    """
    from traceguard.database import record_scan, get_scans

    db_path = tmp_path / "test_history.db"
    init_db(db_path)

    # Clean file with no malware findings
    risk_score = 0
    risk_level = "SAFE"
    integrity_status = "CHANGED"
    findings = []

    rec = determine_recommendation(
        risk_score=risk_score,
        risk_level=risk_level,
        integrity_status=integrity_status,
        findings=findings,
        file_size=1024,
        primary_ext=".pdf"
    )

    assert rec["verdict"] == VERDICT_SUSPICIOUS
    assert "ALERT: File Has Changed" in rec["headline"]

    scan_id = record_scan(
        file_name="Quarterly_Report.pdf",
        sha256_hash="3333333333333333333333333333333333333333333333333333333333333333",
        file_size=1024,
        risk_score=risk_score,
        risk_level=risk_level,
        integrity_status=integrity_status,
        findings=findings,
        recommendation=rec,
        db_path=db_path
    )
    assert scan_id > 0

    scans, count = get_scans(db_path=db_path)
    assert count == 1
    scan = scans[0]
    assert scan["risk_score"] == 0
    assert scan["risk_level"] == "SAFE"
    assert scan["integrity_status"] == "CHANGED"
    assert scan["recommendation"]["verdict"] == VERDICT_SUSPICIOUS

