"""
End-to-End Integration Tests for TRACEGUARD AI
Tests full workflows: scanning synthetic samples, baseline registration,
tamper detection, rule triggers, database persistence, and report generation.
"""

import json
from pathlib import Path
import pytest
from traceguard.synthetic import generate_synthetic_samples
from traceguard.analyzer import analyze_file
from traceguard.risk_engine import evaluate_rules, calculate_risk_score, determine_recommendation
from traceguard.hasher import compare_hashes
from traceguard.database import (
    init_db,
    register_baseline,
    get_baseline_by_identifier,
    get_baseline_by_hash,
    update_baseline,
    record_scan,
    get_scans,
    get_scan_stats,
    clear_history
)
from traceguard.reports import (
    generate_json_report,
    generate_csv_report,
    generate_markdown_summary,
    generate_text_report
)


@pytest.fixture(scope="module")
def setup_integration_env(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("traceguard_test_env")
    samples_dir = tmp_dir / "samples"
    generate_synthetic_samples(samples_dir)
    db_path = tmp_dir / "test_traceguard.db"
    init_db(db_path)
    return {"dir": tmp_dir, "samples_dir": samples_dir, "db_path": db_path}


def test_clean_pdf_baseline_and_tamper_detection(setup_integration_env):
    samples_dir = setup_integration_env["samples_dir"]
    db_path = setup_integration_env["db_path"]

    # 1. Analyze clean PDF
    clean_pdf = samples_dir / "sample_clean_document.pdf"
    analysis_clean = analyze_file(clean_pdf)

    # 2. Register clean PDF as trusted baseline
    b_id = register_baseline(
        identifier=clean_pdf.name,
        file_name=clean_pdf.name,
        sha256_hash=analysis_clean["sha256"],
        file_size=analysis_clean["file_size"],
        trusted_notes="Official release baseline",
        db_path=db_path
    )
    assert b_id > 0

    # 3. Rescan clean PDF: verify UNCHANGED status
    stored_baseline = get_baseline_by_identifier(clean_pdf.name, db_path=db_path)
    assert stored_baseline is not None
    diff_unchanged = compare_hashes(analysis_clean["sha256"], stored_baseline["sha256_hash"])
    assert diff_unchanged["status"] == "UNCHANGED"

    # 4. Scan modified PDF: verify CHANGED status
    modified_pdf = samples_dir / "sample_clean_document_modified.pdf"
    analysis_modified = analyze_file(modified_pdf)
    diff_changed = compare_hashes(analysis_modified["sha256"], stored_baseline["sha256_hash"])
    assert diff_changed["status"] == "CHANGED"
    assert diff_changed["match"] is False


def test_double_extension_rule_trigger(setup_integration_env):
    samples_dir = setup_integration_env["samples_dir"]
    db_path = setup_integration_env["db_path"]

    target = samples_dir / "invoice_march2026.pdf.exe"
    analysis = analyze_file(target)
    findings = evaluate_rules(analysis)
    rule_ids = [f["rule_id"] for f in findings]

    assert "RULE-001" in rule_ids
    risk = calculate_risk_score(findings)
    assert risk["risk_score"] >= 40

    scan_id = record_scan(
        file_name=analysis["file_name"],
        sha256_hash=analysis["sha256"],
        file_size=analysis["file_size"],
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        integrity_status="UNKNOWN",
        findings=findings,
        db_path=db_path
    )
    assert scan_id > 0


def test_magic_mismatch_rule_trigger(setup_integration_env):
    samples_dir = setup_integration_env["samples_dir"]
    target = samples_dir / "disguised_pe_as_png.png"
    analysis = analyze_file(target)
    findings = evaluate_rules(analysis)
    rule_ids = [f["rule_id"] for f in findings]

    assert "RULE-003" in rule_ids
    risk = calculate_risk_score(findings)
    assert risk["risk_score"] >= 50
    assert risk["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]


def test_report_generation(setup_integration_env):
    samples_dir = setup_integration_env["samples_dir"]
    target = samples_dir / "sample_image.png"
    analysis = analyze_file(target)
    findings = evaluate_rules(analysis)
    risk = calculate_risk_score(findings)
    rec = determine_recommendation(risk["risk_score"], risk["risk_level"], "UNCHANGED", findings)

    scan_data = {
        "id": 42,
        "file_name": analysis["file_name"],
        "file_size": analysis["file_size"],
        "file_extension": analysis["primary_extension"],
        "detected_mime": analysis["mime_type"],
        "entropy": analysis["entropy"],
        "sha256_hash": analysis["sha256"],
        "sha1_hash": analysis["sha1"],
        "md5_hash": analysis["md5"],
        "integrity_status": "UNCHANGED",
        "baseline_id": 1,
        "baseline_hash": analysis["sha256"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "findings": findings,
        "recommendation": rec,
        "scanned_at": analysis["timestamp"]
    }

    # JSON report
    json_rep = generate_json_report(scan_data)
    parsed_json = json.loads(json_rep)
    assert parsed_json["target_file"]["name"] == "sample_image.png"
    assert parsed_json["cryptographic_fingerprints"]["sha256"] == analysis["sha256"]
    assert "TRACEGUARD AI" in parsed_json["generator"]["application"]

    # CSV report
    csv_rep = generate_csv_report([scan_data])
    assert "sample_image.png" in csv_rep
    assert analysis["sha256"] in csv_rep

    # Markdown report
    md_rep = generate_markdown_summary(scan_data)
    assert "sample_image.png" in md_rep
    assert "TRACEGUARD AI" in md_rep

    # Plain text report (.txt)
    txt_rep = generate_text_report(scan_data)
    assert "sample_image.png" in txt_rep
    assert "TRACEGUARD AI" in txt_rep
    assert analysis["sha256"] in txt_rep
    assert "UNCHANGED" in txt_rep
    assert "Risk Level" in txt_rep
    assert "Risk Score" in txt_rep
    assert "Scan Timestamp" in txt_rep
    assert "Recommended Next Steps" in txt_rep


def test_text_report_generation_changed_baseline(setup_integration_env):
    """
    Ensures that when a file has changed from its trusted baseline,
    the generated text report clearly and prominently displays the baseline-change
    warning and does NOT label the file as safe without that warning.
    """
    scan_data = {
        "file_name": "config_tampered.json",
        "file_size": 2048,
        "file_size_formatted": "2.00 KB",
        "file_extension": ".json",
        "detected_mime": "application/json",
        "entropy": 4.1234,
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha1_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "integrity_status": "CHANGED",
        "baseline_id": 10,
        "baseline_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "risk_score": 25,
        "risk_level": "LOW",
        "findings": [],
        "recommendation": {
            "verdict": "Needs Review",
            "headline": "⚠️ ALERT: File Has Changed",
            "summary": "This file is different from the trusted version saved earlier. Review the changes before using it.",
            "recommended_actions": [
                "Confirm whether this file was intentionally updated.",
                "Do not open if unexpected."
            ]
        },
        "scanned_at": "2026-10-15T22:00:00Z"
    }

    txt_rep = generate_text_report(scan_data)
    assert "config_tampered.json" in txt_rep
    assert "CHANGED" in txt_rep
    assert "CRITICAL INTEGRITY ALERT" in txt_rep
    assert "0000000000000000000000000000000000000000000000000000000000000000" in txt_rep
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in txt_rep
    assert "Confirm whether this file was intentionally updated." in txt_rep


def test_text_report_generation_with_findings(setup_integration_env):
    """
    Ensures that when detection rules trigger, the findings and their explanations
    are clearly listed in the text report along with risk level and score.
    """
    samples_dir = setup_integration_env["samples_dir"]
    target = samples_dir / "disguised_pe_as_png.png"
    analysis = analyze_file(target)
    findings = evaluate_rules(analysis)
    risk = calculate_risk_score(findings)
    rec = determine_recommendation(risk["risk_score"], risk["risk_level"], "UNKNOWN", findings)

    scan_data = {
        "file_name": analysis["file_name"],
        "file_size": analysis["file_size"],
        "file_extension": analysis["primary_extension"],
        "detected_mime": analysis["mime_type"],
        "entropy": analysis["entropy"],
        "sha256_hash": analysis["sha256"],
        "sha1_hash": analysis["sha1"],
        "md5_hash": analysis["md5"],
        "integrity_status": "UNKNOWN",
        "baseline_id": None,
        "baseline_hash": None,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "findings": findings,
        "recommendation": rec,
        "scanned_at": analysis["timestamp"]
    }

    txt_rep = generate_text_report(scan_data)
    assert analysis["file_name"] in txt_rep
    assert f"{risk['risk_score']} / 100" in txt_rep
    assert f"Risk Level          : {risk['risk_level']}" in txt_rep
    assert "RULE-003" in txt_rep
    assert "Observed Evidence" in txt_rep


def test_baseline_lookup_by_hash_fallback(setup_integration_env):
    """
    Regression test for line 525-543 of app.py:
    Ensures that when a file is investigated with a different filename than the registered identifier,
    get_baseline_by_hash successfully finds the baseline by SHA-256 and verifies it as UNCHANGED.
    """
    db_path = setup_integration_env["db_path"]
    samples_dir = setup_integration_env["samples_dir"]

    # Use clean PNG sample
    target_sample = samples_dir / "sample_image.png"
    analysis = analyze_file(target_sample)

    # Register under an official release identifier
    unique_ident = "GOLD_MASTER_IMAGE_2026"
    register_baseline(
        identifier=unique_ident,
        file_name="brand_logo.png",
        sha256_hash=analysis["sha256"],
        file_size=analysis["file_size"],
        trusted_notes="Golden baseline for logo",
        db_path=db_path
    )

    # Simulate investigating the file when filename is "downloaded_copy.pdf" (identifier mismatch)
    filename_investigated = "downloaded_copy.pdf"
    match_by_name = get_baseline_by_identifier(filename_investigated, db_path=db_path)
    assert match_by_name is None, "Should not match by identifier"

    # Fallback to lookup by SHA-256
    match_by_hash = get_baseline_by_hash(analysis["sha256"], db_path=db_path)
    assert match_by_hash is not None, "get_baseline_by_hash must find the baseline"
    assert match_by_hash["identifier"] == unique_ident

    # Verify UNCHANGED status
    diff_res = compare_hashes(analysis["sha256"], match_by_hash["sha256_hash"])
    assert diff_res["status"] == "UNCHANGED"
    assert diff_res["match"] is True


def test_app_py_exports_and_imports():
    """
    Verifies that app.py has all necessary database functions imported into its namespace.
    """
    import ast
    with open("app.py", encoding="utf-8") as f:
        tree = ast.parse(f.read())

    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "traceguard.database":
            for alias in node.names:
                imported_names.add(alias.name)

    required_funcs = {
        "init_db",
        "get_scan_stats",
        "get_scans",
        "get_scan_by_id",
        "record_scan",
        "list_baselines",
        "get_baseline_by_identifier",
        "get_baseline_by_hash",
        "register_baseline",
        "update_baseline",
        "delete_baseline",
        "clear_history"
    }

    assert required_funcs.issubset(imported_names), f"Missing imports in app.py: {required_funcs - imported_names}"
