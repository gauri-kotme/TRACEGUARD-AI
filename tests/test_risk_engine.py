"""
Tests for traceguard.risk_engine
Includes tests for two-level threat verdicts, dual explanations,
and the distinction between risk score and malware probability.
"""

from traceguard.risk_engine import (
    evaluate_rules,
    calculate_risk_score,
    determine_recommendation,
    determine_verdict,
)
from traceguard.config import (
    VERDICT_LIKELY_SAFE,
    VERDICT_SUSPICIOUS,
    VERDICT_LIKELY_MALICIOUS,
    VERDICT_UNABLE_TO_DETERMINE,
)


def test_rule_double_extension():
    analysis = {
        "file_name": "urgent_invoice.pdf.exe",
        "primary_extension": ".exe",
        "filename_anomalies": {
            "all_suffixes": [".pdf", ".exe"],
            "has_spoof_chars": False
        },
        "file_size": 1024,
        "entropy": 4.5,
        "detected_signature": None
    }
    findings = evaluate_rules(analysis)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE-001" in rule_ids
    score_data = calculate_risk_score(findings)
    assert score_data["risk_score"] >= 40

    # Verify dual explanations exist
    finding = next(f for f in findings if f["rule_id"] == "RULE-001")
    assert "simple_explanation" in finding
    assert "technical_details" in finding
    assert "why_triggered" in finding
    assert "limitations" in finding
    assert "sandbox" in finding["recommended_action"].lower() or "quarantine" in finding["recommended_action"].lower()


def test_rule_magic_mismatch_executable():
    analysis = {
        "file_name": "nature_photo.png",
        "primary_extension": ".png",
        "filename_anomalies": {
            "all_suffixes": [".png"],
            "has_spoof_chars": False
        },
        "file_size": 2048,
        "entropy": 5.0,
        "detected_signature": {
            "id": "PE_EXE",
            "name": "Windows PE Executable / DLL",
            "category": "executable",
            "mime": "application/x-dosexec",
            "expected_extensions": [".exe", ".dll"]
        }
    }
    findings = evaluate_rules(analysis)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE-003" in rule_ids
    score_data = calculate_risk_score(findings)
    assert score_data["risk_score"] >= 50

    # Disguised executable should result in Likely Malicious
    rec = determine_recommendation(
        risk_score=score_data["risk_score"],
        risk_level=score_data["risk_level"],
        integrity_status="UNKNOWN",
        findings=findings,
        file_size=analysis["file_size"],
        primary_ext=analysis["primary_extension"]
    )
    assert rec["verdict"] == VERDICT_LIKELY_MALICIOUS


def test_clean_file_scoring():
    analysis = {
        "file_name": "clean_document.pdf",
        "primary_extension": ".pdf",
        "filename_anomalies": {
            "all_suffixes": [".pdf"],
            "has_spoof_chars": False
        },
        "file_size": 5000,
        "entropy": 4.2,
        "detected_signature": {
            "id": "PDF_DOC",
            "name": "Adobe Portable Document Format (PDF)",
            "category": "document",
            "mime": "application/pdf",
            "expected_extensions": [".pdf"]
        }
    }
    findings = evaluate_rules(analysis)
    assert len(findings) == 0
    score_data = calculate_risk_score(findings)
    assert score_data["risk_score"] == 0
    assert score_data["risk_level"] == "SAFE"

    rec = determine_recommendation(
        risk_score=0,
        risk_level="SAFE",
        integrity_status="UNCHANGED",
        findings=findings,
        file_size=analysis["file_size"],
        primary_ext=analysis["primary_extension"]
    )
    assert rec["verdict"] == VERDICT_LIKELY_SAFE
    # Ensure safety note clarifies no guarantee of safety
    assert "guarantee of absolute safety" in rec["disclaimer"].lower() or "not a guarantee" in rec["disclaimer"].lower()


def test_recommendation_changed_baseline():
    rec = determine_recommendation(
        risk_score=10,
        risk_level="SAFE",
        integrity_status="CHANGED",
        findings=[]
    )
    assert "MISMATCH" in rec["headline"] or "ALERT" in rec["headline"]
    assert rec["badge_color"] == "#ef4444"


def test_high_entropy_is_suspicious_not_malicious():
    """
    CRITICAL REQUIREMENT:
    Do not classify a file as malicious merely because its entropy is high.
    High entropy should produce 'Suspicious', NOT 'Likely Malicious'.
    """
    analysis = {
        "file_name": "dense_data.bin",
        "primary_extension": ".bin",
        "filename_anomalies": {
            "all_suffixes": [".bin"],
            "has_spoof_chars": False
        },
        "file_size": 10000,
        "entropy": 7.85, # High entropy
        "detected_signature": None
    }
    findings = evaluate_rules(analysis)
    score_data = calculate_risk_score(findings)

    verdict_info = determine_verdict(
        risk_score=score_data["risk_score"],
        risk_level=score_data["risk_level"],
        integrity_status="UNKNOWN",
        findings=findings,
        file_size=analysis["file_size"],
        primary_ext=analysis["primary_extension"]
    )
    assert verdict_info["verdict"] == VERDICT_SUSPICIOUS
    assert verdict_info["verdict"] != VERDICT_LIKELY_MALICIOUS
    assert "High entropy or non-standard naming alone does NOT prove a file is malicious" in verdict_info["disclaimer"]


def test_zero_byte_is_unable_to_determine():
    """
    CRITICAL REQUIREMENT:
    Zero-byte empty files must produce 'Unable to Determine'.
    """
    analysis = {
        "file_name": "empty.dat",
        "primary_extension": ".dat",
        "filename_anomalies": {
            "all_suffixes": [".dat"],
            "has_spoof_chars": False
        },
        "file_size": 0,
        "entropy": 0.0,
        "detected_signature": None
    }
    findings = evaluate_rules(analysis)
    score_data = calculate_risk_score(findings)

    verdict_info = determine_verdict(
        risk_score=score_data["risk_score"],
        risk_level=score_data["risk_level"],
        integrity_status="UNKNOWN",
        findings=findings,
        file_size=0,
        primary_ext=".dat"
    )
    assert verdict_info["verdict"] == VERDICT_UNABLE_TO_DETERMINE


def test_score_meaning_distinguishes_malware_probability():
    """
    CRITICAL REQUIREMENT:
    Clearly distinguish the risk score from a statistical malware probability.
    For example, a score of 25/100 means 25 points, not a 25% chance of malware.
    """
    rec = determine_recommendation(
        risk_score=25,
        risk_level="LOW",
        integrity_status="UNKNOWN",
        findings=[{
            "rule_id": "RULE-004",
            "name": "Header Mismatch",
            "category": "magic_mismatch",
            "severity": "MEDIUM",
            "points": 25,
            "evidence": "Mismatch observed",
            "simple_explanation": "Simple text",
            "technical_details": "Tech text"
        }],
        file_size=1024,
        primary_ext=".png"
    )
    score_meaning = rec["score_meaning"]
    assert "25/100" in score_meaning or "25 points" in score_meaning
    assert "NOT a" in score_meaning or "not a statistical" in score_meaning.lower() or "not mean a 25% chance" in score_meaning
