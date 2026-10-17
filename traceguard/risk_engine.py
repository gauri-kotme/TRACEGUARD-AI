"""
TRACEGUARD AI - Explainable Risk Engine
Provides user-friendly file threat checking with transparent detection logic.
Distinguishes heuristic risk score from statistical malware probability.
"""

from typing import Dict, Any, List, Optional
from traceguard.config import (
    EXECUTABLE_EXTENSIONS,
    BENIGN_DECOY_EXTENSIONS,
    RISK_LEVEL_SAFE,
    RISK_LEVEL_LOW,
    RISK_LEVEL_MEDIUM,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_CRITICAL,
    RISK_THRESHOLDS,
    VERDICT_LIKELY_SAFE,
    VERDICT_SUSPICIOUS,
    VERDICT_LIKELY_MALICIOUS,
    VERDICT_UNABLE_TO_DETERMINE,
    CATEGORY_NO_WARNINGS,
    CATEGORY_NEEDS_REVIEW,
    CATEGORY_HIGH_RISK,
    CATEGORY_UNABLE_TO_DETERMINE,
    THEME_COLORS,
)

# Friendly risk level descriptions aligned with consistent categories
RISK_LEVEL_DESCRIPTIONS = {
    "SAFE": "No significant warning signs detected based on available checks.",
    "LOW": "No significant warning signs detected based on available checks.",
    "MEDIUM": "Unusual characteristics or warning signs detected. Needs review before opening.",
    "HIGH": "Strong indicators of potentially harmful content or disguise detected. Avoid opening.",
    "CRITICAL": "Strong signs of a potentially harmful file detected. Do not open or execute it.",
    "UNKNOWN": "Insufficient information to assess this file.",
}


def evaluate_rules(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates transparent rules against file analysis results.
    Provides plain-language descriptions and actions for ordinary users,
    while preserving technical indicators for secondary technical inspection.
    """
    findings = []
    filename = analysis.get("file_name", "")
    anomalies = analysis.get("filename_anomalies", {})
    all_suffixes = anomalies.get("all_suffixes", [])
    primary_ext = analysis.get("primary_extension", "").lower()
    signature = analysis.get("detected_signature")
    file_size = analysis.get("file_size", 0)
    entropy = analysis.get("entropy", 0.0)

    # ---------------------------------------------------------
    # RULE-001: Suspicious Double Extension Masquerading
    # ---------------------------------------------------------
    if len(all_suffixes) >= 2:
        terminal_ext = all_suffixes[-1]
        preceding_ext = all_suffixes[-2]

        is_terminal_exec = terminal_ext in EXECUTABLE_EXTENSIONS
        is_preceding_decoy = preceding_ext in BENIGN_DECOY_EXTENSIONS

        if is_terminal_exec and is_preceding_decoy:
            findings.append({
                "rule_id": "RULE-001",
                "name": "Suspicious Double Extension Masquerading",
                "friendly_title": "Disguised file type",
                "category": "extension",
                "severity": "HIGH",
                "points": 40,
                "evidence": f"File has multiple extensions: '{preceding_ext}' followed by executable extension '{terminal_ext}'. Full sequence: {all_suffixes}.",
                "simple_explanation": (
                    "This file has more than one extension (like .pdf.exe). It looks like an ordinary document or photo, "
                    "but it could actually run as a program on your computer. This is often used to trick people into opening unexpected files."
                ),
                "technical_details": (
                    f"Penultimate decoy suffix '{preceding_ext}' is paired with terminal executable suffix '{terminal_ext}'. "
                    "Windows shell executes this via the binary launcher while hiding the final extension in default view."
                ),
                "why_triggered": f"Penultimate suffix '{preceding_ext}' matches document decoy and final suffix '{terminal_ext}' matches executable catalog.",
                "limitations": "Legitimate files rarely combine document MIME suffixes directly with executable extensions.",
                "recommended_action": "Do not open this file. Quarantine or avoid opening it if unexpected, and confirm with the sender or ask an IT specialist."
            })
        elif len(all_suffixes) >= 3:
            findings.append({
                "rule_id": "RULE-001B",
                "name": "Unusual Multiple Extensions Detected",
                "friendly_title": "Unusual multiple extensions",
                "category": "extension",
                "severity": "LOW",
                "points": 15,
                "evidence": f"File contains {len(all_suffixes)} consecutive extensions: {', '.join(all_suffixes)}.",
                "simple_explanation": (
                    "The file name contains three or more extensions. While some software packages use multi-part names, "
                    "excessive extensions can sometimes be used to confuse security checks."
                ),
                "technical_details": f"Identified {len(all_suffixes)} dotted suffix tokens ({all_suffixes}).",
                "why_triggered": f"Encountered 3 or more suffix delimiters in the filename ({len(all_suffixes)}).",
                "limitations": "Common in backup archives and development packages (e.g., .bundle.tar.gz).",
                "recommended_action": "Confirm that the file name matches what you expected from the sender."
            })

    # ---------------------------------------------------------
    # RULE-002: Unicode RTLO / Bidirectional Spoofing
    # ---------------------------------------------------------
        spoof_names = [
            f"{item.get('name', 'Unknown')} ({item.get('char_code') or (hex(ord(item['char'])) if 'char' in item else '')})"
            for item in anomalies.get("spoof_chars", [])
        ]
        findings.append({
            "rule_id": "RULE-002",
            "name": "Bidirectional Unicode Character in Filename",
            "friendly_title": "Hidden name trick detected",
            "category": "evasion",
            "severity": "HIGH",
            "points": 45,
            "evidence": f"Filename contains hidden direction-reversing Unicode characters: {', '.join(spoof_names)}.",
            "simple_explanation": (
                "The filename contains hidden text direction characters that reverse how the name looks on your screen. "
                "This is often used to make a program look like a safe document."
            ),
            "technical_details": "Identified Unicode bidirectional control characters (such as U+202E Right-to-Left Override) within the UTF-8 filename.",
            "why_triggered": "Filename string contains codepoints from the defined UNICODE_SPOOF_CHARS catalog.",
            "limitations": "Legitimate Arabic or Hebrew text may contain directional markers, but rarely combined with executable extensions.",
            "recommended_action": "Do not open this file. Check the true file name with an IT professional or security scanner."
        })

    # ---------------------------------------------------------
    # RULE-003: Executable Disguised as Non-Executable (Magic Mismatch)
    # ---------------------------------------------------------
    if signature and signature.get("category") == "executable":
        if primary_ext not in EXECUTABLE_EXTENSIONS and primary_ext != "":
            findings.append({
                "rule_id": "RULE-003",
                "name": "Executable Binary Disguised Under Non-Executable Extension",
                "friendly_title": "File type does not match its contents",
                "category": "magic_mismatch",
                "severity": "CRITICAL",
                "points": 50,
                "evidence": f"Internal markers identify this as an executable program ({signature['name']}), but it is labeled with extension '{primary_ext}'.",
                "simple_explanation": (
                    "The file is named as an image or document, but the internal file structure shows it is actually a software program. "
                    "Opening it may not work or could run program code."
                ),
                "technical_details": f"Header bytes indicate executable format ({signature['id']}), whereas declared extension is '{primary_ext}'.",
                "why_triggered": f"Header magic identifies category as 'executable' while filename extension '{primary_ext}' is non-executable.",
                "limitations": "Rare in benign files. Could occasionally happen if an installer was saved with an incorrect extension.",
                "recommended_action": "Do not open or double-click this file. Ask an IT specialist to check it before using it."
            })

    # ---------------------------------------------------------
    # RULE-004: Standard File Signature / Extension Mismatch
    # ---------------------------------------------------------
    if signature and signature.get("category") != "executable":
        expected_exts = signature.get("expected_extensions", [])
        if expected_exts and (primary_ext not in expected_exts):
            is_openxml_zip = signature.get("id") == "ZIP_ARCHIVE" and primary_ext in [".docx", ".xlsx", ".pptx", ".jar", ".zip"]
            if not is_openxml_zip:
                findings.append({
                    "rule_id": "RULE-004",
                    "name": "File Header and Extension Type Mismatch",
                    "friendly_title": "File format mismatch",
                    "category": "magic_mismatch",
                    "severity": "MEDIUM",
                    "points": 25,
                    "evidence": f"File content matches '{signature['name']}' (expected: {', '.join(expected_exts)}), but file is named with extension '{primary_ext}'.",
                    "simple_explanation": (
                        "The file's name says it is one type of file, but its contents look like a different file type "
                        "(for example, a JPEG image named with a PNG extension). This often happens by accident when files are renamed."
                    ),
                    "technical_details": f"Header signature matched '{signature['name']}', which expects extensions {expected_exts}, differing from '{primary_ext}'.",
                    "why_triggered": f"Magic bytes represent a valid format, but differ from declared extension '{primary_ext}'.",
                    "limitations": "Very common when photos or documents are saved with the wrong extension name.",
                    "recommended_action": "Confirm with whoever sent or saved the file that the extension is correct."
                })

    # ---------------------------------------------------------
    # RULE-005: High Entropy (Encrypted, Compressed, or Packed)
    # ---------------------------------------------------------
    # File formats that naturally contain compressed or high-entropy data:
    naturally_compressed_exts = {
        # Archives
        ".zip", ".gz", ".tgz", ".7z", ".rar", ".tar", ".bz2", ".xz", ".cab", ".iso",
        # Documents using Deflate / ZIP streams
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar", ".apk",
        # Media (images, audio, video)
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mp3", ".m4a", ".mov",
        ".avi", ".mkv", ".webm", ".flac", ".ogg"
    }

    is_natural_compressed = primary_ext in naturally_compressed_exts
    has_matching_signature = False
    if signature:
        expected = signature.get("expected_extensions", [])
        if primary_ext in expected or (signature.get("id") == "ZIP_ARCHIVE" and primary_ext in [".docx", ".xlsx", ".pptx", ".jar", ".apk"]):
            has_matching_signature = True
    elif primary_ext in naturally_compressed_exts:
        # Benign default if signature catalog does not cover extension
        has_matching_signature = True

    if entropy >= 7.45 and file_size > 512:
        has_other_anomalies = (
            anomalies.get("is_double_extension")
            or anomalies.get("has_spoof_chars")
            or len(all_suffixes) >= 2
        )
        if is_natural_compressed and has_matching_signature and not has_other_anomalies:
            # Expected high entropy in valid compressed document or media format
            # Impact is lowered to 5 points (severity LOW), so the file stays in the "No significant warning signs detected" band (< 20)
            findings.append({
                "rule_id": "RULE-005",
                "name": "Compressed Format Content (Expected High Entropy)",
                "friendly_title": "Expected compressed content",
                "category": "structural",
                "severity": "LOW",
                "points": 5,
                "evidence": f"File contains compressed data streams (byte randomness: {entropy:.2f} / 8.00).",
                "simple_explanation": (
                    f"This {primary_ext.upper().replace('.', '') or 'file'} contains compressed content (such as embedded fonts, images, or compressed data streams), "
                    "which naturally increases byte randomness. Because this file has a valid format and no other warning signs, this is expected behavior."
                ),
                "technical_details": f"Measured Shannon entropy is {entropy:.3f} / 8.0000 on valid {primary_ext} format.",
                "why_triggered": f"Entropy {entropy:.3f} >= 7.45 is normal for valid {primary_ext} documents with compressed streams.",
                "limitations": "Compressed streams and media naturally exhibit high byte entropy.",
                "recommended_action": "No action needed if you trust the source of this file. This level of randomness is normal for compressed documents."
            })
        else:
            # Unexpected high entropy on uncompressed format (.bin, .txt, .csv) or format with other anomalies
            findings.append({
                "rule_id": "RULE-005",
                "name": "Abnormally High Shannon Entropy",
                "friendly_title": "Unusual file content detected",
                "category": "structural",
                "severity": "MEDIUM",
                "points": 25,
                "evidence": f"File contents have an unusually high level of randomness (density score {entropy:.2f} / 8.00).",
                "simple_explanation": (
                    "The contents of this file look more random than expected for this file type. "
                    "This can happen with normal file compression or because a file contains encrypted or hidden content. "
                    "This warning alone does not mean the file contains malware."
                ),
                "technical_details": f"Header sample entropy of {entropy:.3f} exceeds the 7.45 threshold on non-archive file '{primary_ext}'.",
                "why_triggered": f"Entropy score {entropy:.3f} >= 7.45 on a non-archive file of size > 512 bytes.",
                "limitations": "High entropy is completely normal in encrypted files, password-protected documents, photos, and compressed files.",
                "recommended_action": "If this is a normal compressed or media file, this warning is expected. If it was an unexpected attachment, scan it before opening."
            })

    # ---------------------------------------------------------
    # RULE-006: Standalone Executable Script Extension
    # ---------------------------------------------------------
    script_exts = {".vbs", ".hta", ".wsf", ".ps1", ".bat", ".cmd", ".js"}
    if primary_ext in script_exts and len(all_suffixes) == 1:
        findings.append({
            "rule_id": "RULE-006",
            "name": "Direct Executable Script Detected",
            "friendly_title": "Script file detected",
            "category": "extension",
            "severity": "LOW",
            "points": 20,
            "evidence": f"File uses '{primary_ext}' extension, a script format that can run commands directly.",
            "simple_explanation": (
                "This file is a computer script that can run commands directly on your machine. Only open it if you know and trust whoever sent it."
            ),
            "technical_details": f"Standalone script extension '{primary_ext}' executes in host scripting environments.",
            "why_triggered": f"Extension '{primary_ext}' matches the standalone script extension list.",
            "limitations": "Commonly used for legitimate system administration, backups, and setup routines.",
            "recommended_action": "Only open or run this script if you know who created it and understand what it does."
        })

    # ---------------------------------------------------------
    # RULE-007: Trailing Space or Dot Evasion
    # ---------------------------------------------------------
    if anomalies.get("has_trailing_space") or anomalies.get("has_trailing_dot"):
        evidence_text = []
        if anomalies.get("has_trailing_space"):
            evidence_text.append("ends with extra space")
        if anomalies.get("has_trailing_dot"):
            evidence_text.append("ends with extra period")
        findings.append({
            "rule_id": "RULE-007",
            "name": "Filename Trailing Character Evasion",
            "friendly_title": "Unusual filename characters",
            "category": "evasion",
            "severity": "MEDIUM",
            "points": 20,
            "evidence": f"File name {' and '.join(evidence_text)}.",
            "simple_explanation": "The file name ends with extra spaces or dots. This can confuse normal file checks.",
            "technical_details": "Filename string ends with trailing whitespace or period characters.",
            "why_triggered": "Filename ends with trailing whitespace or trailing dot.",
            "limitations": "Can result from accidental user typos during manual renaming.",
            "recommended_action": "Rename the file to remove trailing spaces or dots before using it."
        })

    # ---------------------------------------------------------
    # RULE-008: Empty (Zero-Byte) File
    # ---------------------------------------------------------
    if file_size == 0:
        findings.append({
            "rule_id": "RULE-008",
            "name": "Zero-Byte / Empty File",
            "friendly_title": "Empty file",
            "category": "structural",
            "severity": "LOW",
            "points": 10,
            "evidence": "File contains 0 bytes of content.",
            "simple_explanation": "This file contains zero bytes of data. It might be an incomplete download or an empty placeholder.",
            "technical_details": "Filesize metric is exactly 0 bytes.",
            "why_triggered": "File size is exactly 0 bytes.",
            "limitations": "Zero-byte files are commonly created as temporary lock markers or aborted downloads.",
            "recommended_action": "Check if the download was interrupted, or re-download the file from the original source."
        })

    # ---------------------------------------------------------
    # RULE-009: Missing Strict Expected Header Magic
    # ---------------------------------------------------------
    strict_formats = {
        ".pdf": b"%PDF-",
        ".png": b"\x89PNG\r\n\x1a\n",
        ".jpg": b"\xff\xd8\xff",
        ".jpeg": b"\xff\xd8\xff"
    }
    if primary_ext in strict_formats and file_size > 0:
        header_sample = analysis.get("header_hex", "")
        if not signature or (primary_ext not in signature.get("expected_extensions", [])):
            findings.append({
                "rule_id": "RULE-009",
                "name": "Missing Required Magic Bytes for Declared Format",
                "friendly_title": "Damaged or unrecognized file format",
                "category": "integrity",
                "severity": "MEDIUM",
                "points": 25,
                "evidence": f"File has extension '{primary_ext}' but is missing the expected format opening markers.",
                "simple_explanation": (
                    "The file claims to be a specific format (like PDF or PNG), but it does not start with the expected digital markers. "
                    "It might be damaged or not what it claims to be."
                ),
                "technical_details": f"Declared extension '{primary_ext}' requires specific magic byte prefix, but header failed signature check.",
                "why_triggered": f"Declared format '{primary_ext}' lacks required magic bytes in initial 16 bytes.",
                "limitations": "Can occur if a download was cut off midway or if the file was corrupted.",
                "recommended_action": "Verify file integrity with the sender. If it does not open properly, ask for a fresh copy."
            })

    return findings


def calculate_risk_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes a transparent, capped risk score (0-100) from rule findings.
    Caps category contributions to prevent score inflation from correlated findings.
    """
    category_caps = {
        "magic_mismatch": 50,
        "extension": 40,
        "evasion": 45,
        "structural": 25,
        "integrity": 25
    }

    category_points = {cat: 0 for cat in category_caps}
    breakdown = []

    for f in findings:
        cat = f.get("category", "structural")
        raw_pts = f.get("points", 0)
        curr = category_points.get(cat, 0)
        cap = category_caps.get(cat, 50)

        allowable = max(0, min(raw_pts, cap - curr))
        category_points[cat] = curr + allowable

        breakdown.append({
            "rule_id": f["rule_id"],
            "name": f["name"],
            "friendly_title": f.get("friendly_title", f["name"]),
            "severity": f["severity"],
            "raw_points": raw_pts,
            "effective_points": allowable,
            "category": cat
        })

    total_score = min(100, sum(category_points.values()))

    if total_score == 0:
        risk_level = "SAFE"
    elif total_score < 20:
        risk_level = "LOW"
    elif total_score < 70:
        risk_level = "MEDIUM"
    elif total_score < 90:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "risk_score": total_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "category_totals": category_points
    }


def determine_verdict(
    risk_score: int,
    risk_level: str,
    integrity_status: str,
    findings: List[Dict[str, Any]],
    file_size: int = 1,
    primary_ext: str = ""
) -> Dict[str, Any]:
    """
    Determines user-friendly threat verdict based on observable facts:
    - No significant warning signs detected (Likely Safe)
    - Needs review (Suspicious)
    - High risk (Likely Malicious)
    - Unable to determine

    CRUCIAL GUIDELINES:
    1. Do NOT classify as malicious merely because entropy is high or filename is unusual.
    2. 'No significant warning signs detected' only when supported by checks, with explicit note that no detection != guarantee of safety.
    3. Clearly explain what the score means vs statistical malware probability.
    """
    rule_ids = {f.get("rule_id") for f in findings}

    # 1. UNABLE TO DETERMINE
    if file_size == 0 or "RULE-008" in rule_ids:
        return {
            "verdict": VERDICT_UNABLE_TO_DETERMINE,
            "verdict_color": THEME_COLORS["verdict_undetermined"],
            "verdict_reason": "This file is completely empty (0 bytes). There is no content to check.",
            "disclaimer": "An empty file cannot execute, but could indicate an interrupted download or empty marker.",
            "score_meaning": (
                f"This is a risk score based on the warning signs found in the file ({risk_score}/100). "
                "It is NOT a percentage chance of malware."
            )
        }

    if "RULE-009" in rule_ids and len(findings) == 1 and risk_score < 40:
        return {
            "verdict": VERDICT_UNABLE_TO_DETERMINE,
            "verdict_color": THEME_COLORS["verdict_undetermined"],
            "verdict_reason": (
                f"The file claims to be '{primary_ext}' but is missing standard digital markers. "
                "It may be corrupted or an unusual format, so we cannot confidently classify it."
            ),
            "disclaimer": "We do not have enough information to confidently classify this file.",
            "score_meaning": (
                f"This is a risk score based on the warning signs found in the file ({risk_score}/100). "
                "It is NOT a percentage chance of malware."
            )
        }

    # 2. HIGH RISK (LIKELY MALICIOUS)
    has_disguised_executable = "RULE-003" in rule_ids
    has_double_ext_masquerade = "RULE-001" in rule_ids
    has_rtlo_evasion = "RULE-002" in rule_ids

    if has_disguised_executable:
        return {
            "verdict": VERDICT_LIKELY_MALICIOUS,
            "verdict_color": THEME_COLORS["verdict_malicious"],
            "verdict_reason": (
                f"Strong signs of a disguised program were detected. The file is labeled as a document or picture ('{primary_ext}'), "
                "but internally it is an executable program."
            ),
            "disclaimer": "Strong signs of a potentially harmful file were detected. Do not open or execute it.",
            "score_meaning": (
                f"This is a risk score based on the warning signs found in the file ({risk_score}/100). "
                "It is NOT a percentage chance of malware."
            )
        }

    if (has_double_ext_masquerade and (has_rtlo_evasion or risk_score >= 70)) or risk_score >= 70:
        return {
            "verdict": VERDICT_LIKELY_MALICIOUS,
            "verdict_color": THEME_COLORS["verdict_malicious"],
            "verdict_reason": (
                "Multiple strong disguise techniques or elevated risk indicators were detected, designed to deceive users or execute code."
            ),
            "disclaimer": "Strong signs of a potentially harmful file were detected. Do not open or execute it.",
            "score_meaning": (
                f"This is a risk score based on the warning signs found in the file ({risk_score}/100). "
                "It is NOT a percentage chance of malware."
            )
        }

    # 3. NEEDS REVIEW (SUSPICIOUS)
    has_significant_finding = any(f.get("severity") in ["HIGH", "CRITICAL", "MEDIUM"] for f in findings)
    if risk_score >= 20 or integrity_status == "CHANGED" or has_significant_finding:
        reasons = []
        if integrity_status == "CHANGED":
            reasons.append("The file is different from your saved trusted version")
        if has_double_ext_masquerade:
            reasons.append("File has two extensions (like .pdf.exe)")
        if has_rtlo_evasion:
            reasons.append("File name contains hidden characters that reverse text")
        if "RULE-005" in rule_ids:
            reasons.append("File contents look unusually random (could be compressed or encrypted)")
        if "RULE-004" in rule_ids:
            reasons.append("File name does not match its internal format")
        if "RULE-006" in rule_ids:
            reasons.append("File is an executable script")
        if "RULE-007" in rule_ids:
            reasons.append("File name ends with extra spaces or dots")

        reason_str = "; ".join(reasons) if reasons else "Something unusual was detected in this file."

        return {
            "verdict": VERDICT_SUSPICIOUS,
            "verdict_color": THEME_COLORS["verdict_suspicious"],
            "verdict_reason": f"Something unusual was detected in this file: {reason_str}.",
            "disclaimer": (
                "Some unusual signs were detected. Check the file before opening it. "
                "High entropy or non-standard naming alone does NOT prove a file is malicious."
            ),
            "score_meaning": (
                f"This is a risk score based on the warning signs found in the file ({risk_score}/100). "
                "It is NOT a percentage chance of malware."
            )
        }

    # 4. NO SIGNIFICANT WARNING SIGNS DETECTED (LIKELY SAFE)
    return {
        "verdict": VERDICT_LIKELY_SAFE,
        "verdict_color": THEME_COLORS["verdict_safe"],
        "verdict_reason": "No significant warning signs were detected. The file name and format look normal.",
        "disclaimer": (
            "No significant warning signs were detected based on available checks. "
            "Note: This is not a guarantee that the file is 100% safe. Always verify the source before opening."
        ),
        "score_meaning": (
            f"This is a risk score based on the warning signs found in the file ({risk_score}/100). "
            "It is NOT a percentage chance of malware."
        )
    }


def determine_recommendation(
    risk_score: int,
    risk_level: str,
    integrity_status: str,
    findings: List[Dict[str, Any]],
    file_size: int = 1,
    primary_ext: str = ""
) -> Dict[str, Any]:
    """
    Formulates simple, actionable advice for ordinary users.
    Does NOT tell users to use Ghidra, PEStudio, or reverse engineering tools.
    """
    verdict_info = determine_verdict(
        risk_score=risk_score,
        risk_level=risk_level,
        integrity_status=integrity_status,
        findings=findings,
        file_size=file_size,
        primary_ext=primary_ext
    )

    verdict = verdict_info["verdict"]
    badge_color = verdict_info["verdict_color"]
    actions = []

    # Priority 1: Integrity Changed vs Indicator Risk
    if integrity_status == "CHANGED":
        badge_color = "#ef4444"
        headline = "⚠️ ALERT: File Has Changed"
        summary = "This file is different from the trusted version saved earlier. Review the changes before using it."
        actions.append("Confirm whether this file was intentionally updated or replaced.")
        actions.append("If you did not expect this file to change, do not use it until you verify it with the sender.")
        if risk_score >= 40:
            actions.append("Ask an IT or security professional to review the file before opening.")

    elif integrity_status == "UNCHANGED":
        headline = "✅ File Has Not Changed"
        summary = "The file matches the trusted version saved earlier."
        actions.append("This file matches your previously saved trusted version.")
        actions.append("You can proceed with using this file as expected.")

    else: # UNKNOWN
        if verdict == VERDICT_LIKELY_MALICIOUS:
            headline = "🔴 Strong Warning Signs Detected — High Risk"
            summary = "Strong signs of a potentially harmful file were detected. Do not open or execute it."
            actions.append("Do not open or double-click this file.")
            actions.append("If you do not recognize the sender, delete the file.")
            actions.append("Ask an IT or security professional to investigate it before opening.")
        elif verdict == VERDICT_SUSPICIOUS:
            headline = "🟡 Warning Signs Detected — Needs Review"
            summary = "Unusual characteristics or warning signs were detected. Review the file before opening it."
            actions.append("If you know and trust the sender, confirm that this is the expected file.")
            actions.append("If you do not recognize the sender, do not open the file.")
            actions.append("If this file is important, scan it using your organization's approved antivirus/security scanner.")
            actions.append("If multiple warnings appear, ask a security professional to check it.")
        elif verdict == VERDICT_UNABLE_TO_DETERMINE:
            headline = "⚪ Insufficient Information to Assess File"
            summary = "We do not have enough information to confidently classify this file."
            actions.append("Check if the file download was interrupted or incomplete.")
            actions.append("Re-download the file from the original trusted source.")
        else: # Likely Safe
            headline = "🟢 No Significant Warning Signs Detected"
            summary = "No significant warning signs detected based on available checks."
            actions.append("The file looks normal based on our checks.")
            actions.append("Make sure you recognize where the file came from before opening.")
            actions.append("If you trust this version, you can save it as a trusted version below to monitor for future changes.")

    return {
        "headline": headline,
        "summary": summary,
        "verdict": verdict,
        "verdict_color": badge_color,
        "verdict_reason": verdict_info["verdict_reason"],
        "disclaimer": verdict_info["disclaimer"],
        "score_meaning": verdict_info.get("score_meaning") or verdict_info.get("score_explanation", ""),
        "recommended_actions": actions,
        "badge_color": badge_color
    }
