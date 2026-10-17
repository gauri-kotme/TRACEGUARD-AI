"""
TRACEGUARD AI - Report Generation
Produces downloadable JSON, CSV, and Markdown forensic investigation reports.
Includes two-level explanations: simple user explanation and deep technical analyst details.
"""

import csv
import json
import io
import datetime
from typing import Dict, Any, List
from traceguard.config import APP_NAME, TAGLINE, VERSION
from traceguard.analyzer import format_bytes


def generate_json_report(scan: Dict[str, Any]) -> str:
    """
    Produces a comprehensive, structured JSON report of an investigation scan.
    """
    rec = scan.get("recommendation") or {}

    report_dict = {
        "generator": {
            "application": APP_NAME,
            "version": VERSION,
            "tagline": TAGLINE,
            "report_generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        "target_file": {
            "name": scan.get("file_name"),
            "size_bytes": scan.get("file_size"),
            "extension": scan.get("file_extension"),
            "detected_mime": scan.get("detected_mime"),
            "entropy": scan.get("entropy"),
            "scanned_at": scan.get("scanned_at"),
        },
        "threat_verdict": {
            "verdict": rec.get("verdict", "Unable to Determine"),
            "verdict_reason": rec.get("verdict_reason", ""),
            "score_meaning": rec.get("score_meaning", ""),
            "disclaimer": rec.get("disclaimer", "")
        },
        "cryptographic_fingerprints": {
            "sha256": scan.get("sha256_hash"),
            "sha1": scan.get("sha1_hash"),
            "md5": scan.get("md5_hash"),
        },
        "integrity_verification": {
            "status": scan.get("integrity_status"),
            "baseline_id": scan.get("baseline_id"),
            "baseline_sha256": scan.get("baseline_hash"),
            "is_matched": scan.get("integrity_status") == "UNCHANGED",
        },
        "risk_evaluation": {
            "score": scan.get("risk_score"),
            "level": scan.get("risk_level"),
            "findings_count": len(scan.get("findings") or []),
            "findings": scan.get("findings") or [],
        },
        "investigation_recommendation": rec,
        "disclaimer": (
            "TRACEGUARD AI reports provide heuristic indicator scoring and cryptographic baseline comparison. "
            "They are advisory and do not assert absolute safety or replace dedicated endpoint malware protection."
        )
    }

    return json.dumps(report_dict, indent=2)


def generate_csv_report(scans: List[Dict[str, Any]]) -> str:
    """
    Generates CSV data for one or more scan records.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    headers = [
        "scan_id",
        "scanned_at",
        "file_name",
        "verdict",
        "sha256_hash",
        "sha1_hash",
        "md5_hash",
        "file_size_bytes",
        "file_extension",
        "detected_mime",
        "entropy",
        "integrity_status",
        "baseline_hash",
        "risk_score",
        "risk_level",
        "findings_count",
        "findings_rule_ids",
        "recommendation_headline"
    ]
    writer.writerow(headers)

    for s in scans:
        findings = s.get("findings") or []
        rec = s.get("recommendation") or {}
        rule_ids = "; ".join([f.get("rule_id", "") for f in findings])
        verdict = rec.get("verdict", "Unable to Determine")

        writer.writerow([
            s.get("id", ""),
            s.get("scanned_at", ""),
            s.get("file_name", ""),
            verdict,
            s.get("sha256_hash", ""),
            s.get("sha1_hash", ""),
            s.get("md5_hash", ""),
            s.get("file_size", 0),
            s.get("file_extension", ""),
            s.get("detected_mime", ""),
            s.get("entropy", 0.0),
            s.get("integrity_status", "UNKNOWN"),
            s.get("baseline_hash", ""),
            s.get("risk_score", 0),
            s.get("risk_level", "SAFE"),
            len(findings),
            rule_ids,
            rec.get("headline", "")
        ])

    return output.getvalue()


def generate_markdown_summary(scan: Dict[str, Any]) -> str:
    """
    Generates a readable Markdown summary of the scan with simple and technical views.
    """
    findings = scan.get("findings") or []
    rec = scan.get("recommendation") or {}
    scanned_at = scan.get("scanned_at", "N/A")
    verdict = rec.get("verdict", "Unable to Determine")

    lines = [
        f"# {APP_NAME} — Threat Investigation Report",
        f"*{TAGLINE}*",
        "",
        f"**Timestamp:** `{scanned_at}`  ",
        f"**Target File:** `{scan.get('file_name')}`  ",
        f"**File Size:** `{scan.get('file_size')} bytes`  ",
        f"**Verdict:** **{verdict}**  ",
        f"**Heuristic Risk Score:** `{scan.get('risk_score')}/100` (`{scan.get('risk_level')}`)",
        f"**Integrity Status:** `{scan.get('integrity_status')}`  ",
        "",
        "## Threat Summary & Verdict Rationale",
        f"**Verdict:** {verdict}  ",
        f"{rec.get('verdict_reason', '')}",
        "",
        f"> **Score Explanation:** {rec.get('score_meaning', 'Risk score is an additive heuristic index, not a statistical malware probability.')}",
        "",
        "## Cryptographic Hashes",
        f"- **SHA-256 (Integrity Anchor):** `{scan.get('sha256_hash')}`",
        f"- **SHA-1 (Legacy):** `{scan.get('sha1_hash')}`",
        f"- **MD5 (Legacy):** `{scan.get('md5_hash')}`",
        "",
        "## Integrity Baseline Comparison",
    ]

    status = scan.get("integrity_status")
    if status == "UNCHANGED":
        lines.append(f"✅ **UNCHANGED:** Matches stored baseline (`{scan.get('baseline_hash')}`).")
    elif status == "CHANGED":
        lines.append(f"⚠️ **CHANGED:** Differs from baseline (`{scan.get('baseline_hash')}`).")
    else:
        lines.append("ℹ️ **UNKNOWN:** No trusted baseline registered for this file identifier.")

    lines.extend([
        "",
        "## Detected Indicators & Dual Explanations",
    ])

    if not findings:
        lines.append("No suspicious indicators or anomalies detected for this file.")
    else:
        for f in findings:
            lines.append(f"### [{f.get('severity')}] {f.get('rule_id')}: {f.get('name')}")
            lines.append(f"- **Simple Explanation:** {f.get('simple_explanation', f.get('evidence', ''))}")
            lines.append(f"- **Technical Details:** {f.get('technical_details', f.get('evidence', ''))}")
            lines.append(f"- **Evidence:** {f.get('evidence')}")
            if f.get("why_triggered"):
                lines.append(f"- **Why Triggered:** {f.get('why_triggered')}")
            if f.get("limitations"):
                lines.append(f"- **Limitations / False Positive Context:** {f.get('limitations')}")
            lines.append(f"- **Remediation Action:** {f.get('recommended_action')}")
            lines.append(f"- **Score Contribution:** `+{f.get('points')}` pts")
            lines.append("")

    lines.extend([
        "## Safe Remediation Guidance",
        f"**Headline:** {rec.get('headline', 'Standard Advisory')}",
        "",
        f"{rec.get('summary', '')}",
        "",
        "### Recommended Actions:",
    ])

    for act in rec.get("recommended_actions", []):
        lines.append(f"- {act}")

    lines.extend([
        "",
        "---",
        f"*Disclaimer: {rec.get('disclaimer', 'TRACEGUARD AI assessments are heuristic and advisory.')}*"
    ])

    return "\n".join(lines)


def generate_text_report(scan: Dict[str, Any]) -> str:
    """
    Produces a clean, human-readable plain text (.txt) investigation report.
    Includes target file details, risk score, verdict, baseline change warning,
    detected findings, and safe remediation guidance.
    """
    rec = scan.get("recommendation") or {}
    findings = scan.get("findings") or []
    scanned_at = scan.get("scanned_at", "N/A")
    file_size = scan.get("file_size", 0)
    file_size_formatted = scan.get("file_size_formatted") or format_bytes(file_size)
    verdict = rec.get("verdict", "Unable to Determine")
    risk_score = scan.get("risk_score", 0)
    risk_level = scan.get("risk_level", "SAFE")
    integrity_status = scan.get("integrity_status", "UNKNOWN")
    baseline_hash = scan.get("baseline_hash")

    lines = [
        "=" * 78,
        f"                   {APP_NAME} — FILE INVESTIGATION REPORT",
        f"                             {TAGLINE}",
        "=" * 78,
        "",
        "SCAN SUMMARY",
        "------------",
        f"File Name           : {scan.get('file_name', 'Unknown')}",
        f"File Size           : {file_size_formatted} ({file_size:,} bytes)",
        f"File Extension      : {scan.get('file_extension') or '(none)'}",
        f"Detected MIME Type  : {scan.get('detected_mime') or 'Unknown'}",
        f"Scan Timestamp (UTC): {scanned_at}",
        f"Risk Level          : {risk_level}",
        f"Risk Score          : {risk_score} / 100",
        f"Threat Verdict      : {verdict}",
        "",
        "VERDICT & RISK EXPLANATION",
        "--------------------------",
        f"Verdict Details     : {rec.get('verdict_reason') or rec.get('summary', 'Standard assessment.')}",
        f"Score Meaning       : {rec.get('score_meaning', 'Risk score is an additive heuristic index, not a probability of malware.')}",
        "",
        "TRUSTED BASELINE INTEGRITY STATUS",
        "---------------------------------"
    ]

    # Explicit baseline-change handling (never label changed file safe without clear warning)
    if integrity_status == "CHANGED":
        lines.extend([
            "Status: [!] CHANGED (INTEGRITY COMPROMISED / WARNING)",
            f"Stored Baseline SHA-256 : {baseline_hash}",
            f"Current File SHA-256    : {scan.get('sha256_hash')}",
            "",
            "*** CRITICAL INTEGRITY ALERT ***",
            "WARNING: This file has CHANGED from its recorded trusted baseline!",
            "Even if no standalone malware indicators triggered, this file does NOT match",
            "the approved trusted version. Do not treat this file as verified safe without",
            "explicitly verifying that this update was intentional and authorized.",
        ])
    elif integrity_status == "UNCHANGED":
        lines.extend([
            "Status: [✓] UNCHANGED (VERIFIED MATCH)",
            f"Matched Baseline SHA-256: {baseline_hash}",
            "Verification: Matches the trusted baseline registered for this file.",
        ])
    else:  # UNKNOWN
        lines.extend([
            "Status: [i] UNKNOWN (No Saved Baseline)",
            "Verification: No trusted baseline has been saved for this file yet.",
            "You can save this file as a trusted baseline to monitor it for future changes.",
        ])

    entropy_val = scan.get("entropy")
    entropy_str = f"{entropy_val:.4f} / 8.0000" if isinstance(entropy_val, (int, float)) else "N/A"

    lines.extend([
        "",
        "CRYPTOGRAPHIC FINGERPRINTS",
        "--------------------------",
        f"SHA-256 (Primary)   : {scan.get('sha256_hash', 'N/A')}",
        f"SHA-1   (Legacy)    : {scan.get('sha1_hash', 'N/A')}",
        f"MD5     (Legacy)    : {scan.get('md5_hash', 'N/A')}",
        f"Shannon Entropy     : {entropy_str}",
        "",
        f"DETECTED FINDINGS ({len(findings)})",
        "---------------------"
    ])

    if not findings:
        lines.append("No suspicious indicators, disguised extensions, or structural anomalies detected.")
    else:
        for idx, f in enumerate(findings, 1):
            lines.append(f"[{idx}] {f.get('rule_id', 'RULE')}: {f.get('name', 'Finding')}")
            lines.append(f"    Severity          : {f.get('severity', 'MEDIUM')} (+{f.get('points', 0)} pts)")
            lines.append(f"    Category          : {f.get('category', 'general')}")
            lines.append(f"    Simple Explanation: {f.get('simple_explanation', f.get('evidence', ''))}")
            lines.append(f"    Observed Evidence : {f.get('evidence', '')}")
            if f.get("why_triggered"):
                lines.append(f"    Why Triggered     : {f.get('why_triggered')}")
            if f.get("limitations"):
                lines.append(f"    Limitations / FP  : {f.get('limitations')}")
            if f.get("recommended_action"):
                lines.append(f"    Recommended Action: {f.get('recommended_action')}")
            lines.append("")

    lines.extend([
        "",
        "RECOMMENDED ACTION & NEXT STEPS",
        "-------------------------------",
        f"Headline: {rec.get('headline', 'Standard Advisory')}",
        f"Summary : {rec.get('summary', '')}",
        "",
        "Recommended Next Steps:"
    ])

    rec_actions = rec.get("recommended_actions") or []
    if not rec_actions:
        rec_actions = [
            "If you know and trust the sender, confirm that this is the expected file.",
            "If you do not recognize the sender, do not open the file.",
            "If this file is important, scan it using your organization's approved antivirus scanner."
        ]

    for act in rec_actions:
        lines.append(f"  * {act}")

    disclaimer_text = rec.get("disclaimer") or (
        "TRACEGUARD AI assessments are heuristic indicator scoring and cryptographic baseline "
        "comparisons. They are advisory and do not assert absolute safety or replace dedicated "
        "endpoint antivirus protection."
    )

    lines.extend([
        "",
        "=" * 78,
        "DISCLAIMER",
        disclaimer_text,
        "=" * 78
    ])

    return "\n".join(lines)
