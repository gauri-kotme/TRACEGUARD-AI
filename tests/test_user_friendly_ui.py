"""
Unit tests verifying user-friendly terminology and design requirements in TRACEGUARD AI.
"""

from pathlib import Path
from traceguard.risk_engine import (
    evaluate_rules,
    calculate_risk_score,
    determine_recommendation,
    determine_verdict,
    RISK_LEVEL_DESCRIPTIONS,
)
from traceguard.analyzer import analyze_file
from traceguard.synthetic import generate_synthetic_samples


def test_no_reverse_engineering_jargon_in_user_recommendations(tmp_path):
    """
    Ensures that user-facing recommendations NEVER tell ordinary users
    to use Ghidra, PEStudio, reverse-engineering tools, or unpack binaries.
    """
    samples_dir = tmp_path / "samples"
    generate_synthetic_samples(samples_dir)

    forbidden_terms = [
        "ghidra",
        "pestudio",
        "unpack binary",
        "unpacking binaries",
        "reverse engineer",
        "reverse-engineering",
        "disassembler",
    ]

    # Test actual safe disk samples
    for sample_file in samples_dir.glob("*"):
        try:
            analysis = analyze_file(sample_file)
        except OSError:
            # On Windows, filenames with special control characters can raise Errno 22
            continue

        findings = evaluate_rules(analysis)
        risk = calculate_risk_score(findings)
        rec = determine_recommendation(
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            integrity_status="UNKNOWN",
            findings=findings,
            file_size=analysis["file_size"],
            primary_ext=analysis["primary_extension"],
        )

        for action in rec.get("recommended_actions", []):
            for term in forbidden_terms:
                assert term not in action.lower(), f"Forbidden technical jargon '{term}' found in recommendation: {action}"

        for f in findings:
            for term in forbidden_terms:
                assert term not in f.get("simple_explanation", "").lower(), f"Forbidden jargon in explanation: {f}"
                assert term not in f.get("recommended_action", "").lower(), f"Forbidden jargon in action: {f}"

    # Also test diverse synthesized cases in-memory (including RTLO and double extensions)
    test_cases = [
        {"data": b"harmless content", "name": "Quarterly_Summary_\u202egpj.exe"},
        {"data": b"MZ\x90\x00\x03\x00dummy", "name": "document.pdf.exe"},
        {"data": b"MZ\x90\x00\x03\x00dummy", "name": "photo.png"},
        {"data": b"", "name": "empty.dat"},
        {"data": b"Write-Host 'test'", "name": "script.ps1"},
        {"data": b"normal content", "name": "report.pdf   "},
    ]

    for tc in test_cases:
        analysis = analyze_file(tc["data"], filename=tc["name"])
        findings = evaluate_rules(analysis)
        risk = calculate_risk_score(findings)
        rec = determine_recommendation(
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            integrity_status="UNKNOWN",
            findings=findings,
            file_size=analysis["file_size"],
            primary_ext=analysis["primary_extension"],
        )

        for action in rec.get("recommended_actions", []):
            for term in forbidden_terms:
                assert term not in action.lower(), f"Forbidden technical jargon '{term}' found in recommendation: {action}"

        for f in findings:
            for term in forbidden_terms:
                assert term not in f.get("simple_explanation", "").lower(), f"Forbidden jargon in explanation: {f}"
                assert term not in f.get("recommended_action", "").lower(), f"Forbidden jargon in action: {f}"


def test_all_rules_have_plain_language_fields():
    """
    Ensures that every triggered rule provides friendly_title and simple_explanation.
    """
    synthetic_analysis = {
        "file_name": "statement.pdf.exe",
        "file_size": 2048,
        "primary_extension": ".exe",
        "mime_type": "application/x-dosexec",
        "entropy": 7.8,
        "header_hex": "4d5a",
        "header_ascii": "MZ",
        "detected_signature": {
            "id": "PE_EXE",
            "name": "Windows PE",
            "mime": "application/x-dosexec",
            "expected_extensions": [".exe"],
        },
        "filename_anomalies": {
            "all_suffixes": [".pdf", ".exe"],
            "suffix_count": 2,
            "has_spoof_chars": False,
            "has_trailing_space": False,
            "has_trailing_dot": False,
        },
    }
    findings = evaluate_rules(synthetic_analysis)
    assert len(findings) > 0
    for f in findings:
        assert "friendly_title" in f, f"Missing friendly_title in {f['rule_id']}"
        assert "simple_explanation" in f, f"Missing simple_explanation in {f['rule_id']}"
        assert len(f["friendly_title"]) > 0
        assert len(f["simple_explanation"]) > 0


def test_score_meaning_explicitly_disclaims_malware_probability():
    """
    Ensures that score explanation clearly states it is a heuristic score,
    NOT a percentage chance or probability of malware.
    """
    for score in [0, 25, 50, 75, 100]:
        verdict = determine_verdict(
            risk_score=score,
            risk_level="MEDIUM",
            integrity_status="UNKNOWN",
            findings=[],
            file_size=1024,
            primary_ext=".pdf",
        )
        meaning = verdict["score_meaning"]
        assert "NOT a percentage chance of malware" in meaning
        assert "malware probability" not in meaning.lower() or "not a" in meaning.lower()


def test_risk_level_descriptions():
    """
    Validates that user-friendly definitions exist for all risk levels.
    """
    for lvl in ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]:
        assert lvl in RISK_LEVEL_DESCRIPTIONS
        assert len(RISK_LEVEL_DESCRIPTIONS[lvl]) > 10
