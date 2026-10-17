"""
TRACEGUARD AI — File Integrity & Threat Investigation Platform
Tagline: "Verify. Investigate. Trust."

Main Streamlit Application
A user-friendly file threat checker for everyday users,
with an optional advanced technical report for security specialists.
"""

import datetime
import json
from pathlib import Path
import re
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# TraceGuard Core Modules
from traceguard.config import (
    APP_NAME,
    TAGLINE,
    VERSION,
    THEME_COLORS,
    DEFAULT_DB_PATH,
    RISK_LEVEL_SAFE,
    RISK_LEVEL_LOW,
    RISK_LEVEL_MEDIUM,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_CRITICAL,
    VERDICT_LIKELY_SAFE,
    VERDICT_SUSPICIOUS,
    VERDICT_LIKELY_MALICIOUS,
    VERDICT_UNABLE_TO_DETERMINE,
)
from traceguard.database import (
    init_db,
    get_scan_stats,
    get_scans,
    get_scan_by_id,
    record_scan,
    list_baselines,
    get_baseline_by_identifier,
    get_baseline_by_hash,
    register_baseline,
    update_baseline,
    delete_baseline,
    clear_history,
)
from traceguard.analyzer import analyze_file
from traceguard.risk_engine import (
    evaluate_rules,
    calculate_risk_score,
    determine_recommendation,
    determine_verdict,
    RISK_LEVEL_DESCRIPTIONS,
)
from traceguard.hasher import compare_hashes, compute_hashes
from traceguard.reports import (
    generate_json_report,
    generate_csv_report,
    generate_markdown_summary,
    generate_text_report,
)
from traceguard.synthetic import generate_synthetic_samples

# ============================================================================
# PAGE CONFIGURATION & STYLES
# ============================================================================

st.set_page_config(
    page_title=f"{APP_NAME} — {TAGLINE}",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for Cybersecurity Dark Charcoal & Electric Cyan Aesthetic
CUSTOM_CSS = """
<style>
    /* Dark charcoal background setup */
    .stApp {
        background-color: #0d1117;
        color: #f0f6fc;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    /* Main headings */
    h1, h2, h3, h4 {
        color: #f0f6fc;
        font-weight: 600;
        letter-spacing: -0.5px;
    }

    /* Gradient header banner */
    .brand-title {
        font-size: 2.1rem;
        font-weight: 700;
        background: linear-gradient(135deg, #00e5ff 0%, #38bdf8 50%, #2563eb 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0px;
        letter-spacing: 0.5px;
    }

    .brand-tagline {
        color: #8b949e;
        font-size: 0.95rem;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-top: 2px;
        font-weight: 600;
    }

    /* Metric cards */
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 18px 20px;
        margin-bottom: 12px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .metric-card:hover {
        border-color: #00e5ff;
        transform: translateY(-2px);
    }
    .metric-value {
        font-size: 2.0rem;
        font-weight: 700;
        color: #00e5ff;
        line-height: 1.1;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 4px;
    }

    /* Hash display container */
    .hash-box {
        background-color: #090d12;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 10px 14px;
        font-family: "Courier New", Courier, monospace;
        font-size: 0.88rem;
        color: #00e5ff;
        word-break: break-all;
        margin: 6px 0;
    }

    /* Risk and Status Badges */
    .badge-pill {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .badge-safe { background-color: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }
    .badge-low { background-color: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #38bdf8; }
    .badge-medium { background-color: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }
    .badge-high { background-color: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }

    /* Verdict Banner Card */
    .verdict-card {
        background: #161b22;
        border-radius: 10px;
        padding: 22px 26px;
        margin: 18px 0 20px 0;
        box-shadow: 0 4px 18px rgba(0,0,0,0.35);
        border: 1px solid #30363d;
    }
    .verdict-safe { border-left: 8px solid #10b981; }
    .verdict-suspicious { border-left: 8px solid #f59e0b; }
    .verdict-malicious { border-left: 8px solid #ef4444; }
    .verdict-undetermined { border-left: 8px solid #94a3b8; }

    /* Finding card */
    .finding-card {
        background: #161b22;
        border-left: 4px solid #f59e0b;
        border-radius: 0 8px 8px 0;
        padding: 16px 20px;
        margin-bottom: 14px;
        border-top: 1px solid #30363d;
        border-right: 1px solid #30363d;
        border-bottom: 1px solid #30363d;
    }
    .finding-card-critical { border-left-color: #ef4444; }
    .finding-card-high { border-left-color: #f97316; }
    .finding-card-medium { border-left-color: #f59e0b; }
    .finding-card-low { border-left-color: #38bdf8; }

    /* Hash diff styling */
    .hash-char-match { color: #10b981; }
    .hash-char-diff { color: #ef4444; font-weight: bold; background: rgba(239, 68, 68, 0.15); padding: 0 1px; }

    /* Plotly modebar, tooltip, and tester suppression */
    .modebar, .modebar-container, .modebar-btn, .modebar-btn__tooltip, .plotly-notifier {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
    }
    #js-plotly-tester {
        display: none !important;
    }

    /* Streamlit components tweaking */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #161b22;
        border-radius: 6px;
        padding: 8px 16px;
        color: #8b949e;
        border: 1px solid #30363d;
    }
    .stTabs [aria-selected="true"] {
        background-color: #21262d !important;
        color: #00e5ff !important;
        border-color: #00e5ff !important;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Initialize SQLite database
init_db(DEFAULT_DB_PATH)

# Ensure sample files exist for instant demo
SAMPLES_DIR = Path("samples")
if not SAMPLES_DIR.exists() or len(list(SAMPLES_DIR.glob("*"))) < 4:
    generate_synthetic_samples(SAMPLES_DIR)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def render_risk_badge(level: str) -> str:
    """Returns HTML for styled risk badge pill."""
    lvl = (level or "LOW").upper()
    css_class = f"badge-{lvl.lower()}"
    return f'<span class="badge-pill {css_class}">{lvl}</span>'


def render_verdict_badge(verdict: str) -> str:
    """Returns HTML for prominent user-friendly threat verdict badge."""
    v = (verdict or "Unable to determine").strip().lower()
    if "safe" in v or "no significant" in v:
        return '<span class="badge-pill badge-safe" style="font-size: 1.05rem; padding: 6px 18px;">🟢 NO SIGNIFICANT WARNINGS</span>'
    elif "review" in v or "suspicious" in v:
        return '<span class="badge-pill badge-medium" style="font-size: 1.05rem; padding: 6px 18px;">🟡 NEEDS REVIEW</span>'
    elif "high" in v or "malicious" in v:
        return '<span class="badge-pill badge-critical" style="font-size: 1.05rem; padding: 6px 18px;">🔴 HIGH RISK</span>'
    else:
        return '<span class="badge-pill" style="font-size: 1.05rem; padding: 6px 18px; background-color: #21262d; color: #8b949e; border: 1px solid #484f58;">⚪ UNABLE TO DETERMINE</span>'


def render_integrity_badge(status: str) -> str:
    """Returns HTML for styled integrity status badge."""
    stat = (status or "UNKNOWN").upper()
    if stat == "UNCHANGED":
        return '<span class="badge-pill badge-safe">✅ File Has Not Changed</span>'
    elif stat == "CHANGED":
        return '<span class="badge-pill badge-critical">⚠️ File Has Changed</span>'
    else:
        return '<span class="badge-pill" style="background-color: #30363d; color: #8b949e; border: 1px solid #484f58;">ℹ️ No Saved Trusted Version</span>'


def render_hash_diff_html(current_hash: str, baseline_hash: str) -> str:
    """Renders side-by-side character-level diff highlighting for two hashes."""
    if not baseline_hash:
        return f'<div class="hash-box">{current_hash}</div>'

    cur = current_hash.lower()
    base = baseline_hash.lower()

    cur_spans = []
    base_spans = []

    max_len = max(len(cur), len(base))
    for i in range(max_len):
        c = cur[i] if i < len(cur) else ""
        b = base[i] if i < len(base) else ""

        if c == b:
            cur_spans.append(f'<span class="hash-char-match">{c}</span>')
            base_spans.append(f'<span class="hash-char-match">{b}</span>')
        else:
            cur_spans.append(f'<span class="hash-char-diff">{c or "·"}</span>')
            base_spans.append(f'<span class="hash-char-diff">{b or "·"}</span>')

    return f"""
    <div style="font-family: monospace; font-size: 0.88rem; line-height: 1.6; background: #090d12; border: 1px solid #30363d; border-radius: 6px; padding: 12px;">
        <div style="color: #8b949e; margin-bottom: 4px;">CURRENT FILE FINGERPRINT (SHA-256):</div>
        <div style="word-break: break-all; margin-bottom: 10px;">{''.join(cur_spans)}</div>
        <div style="color: #8b949e; margin-bottom: 4px;">TRUSTED BASELINE FINGERPRINT (SHA-256):</div>
        <div style="word-break: break-all;">{''.join(base_spans)}</div>
    </div>
    """


# ============================================================================
# SIDEBAR NAVIGATION
# ============================================================================

with st.sidebar:
    st.markdown(
        f"""
        <div style="padding: 10px 0 20px 0;">
            <div class="brand-title">🛡️ {APP_NAME}</div>
            <div class="brand-tagline">{TAGLINE}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    NAV_PAGES = [
        "🛡️ File Safety Check",
        "📊 Protection Overview",
        "📁 Trusted Files",
        "📜 Scan History",
        "📄 Download Reports",
        "ℹ️ About"
    ]

    nav_page = st.radio(
        "Navigation",
        NAV_PAGES,
        index=0,
        label_visibility="collapsed"
    )

    st.markdown("---")

    # Quick summary stats in sidebar
    stats = get_scan_stats(DEFAULT_DB_PATH)
    changed_color = "#ef4444" if stats['changed_count'] > 0 else "#8b949e"
    st.markdown(
        f"""
        <div style="font-size: 0.85rem; color: #8b949e; line-height: 1.8;">
            <div>📄 <b>Files Checked:</b> <span style="color: #00e5ff; font-weight: 600;">{stats['total_scans']}</span></div>
            <div>🛡️ <b>Trusted Files Saved:</b> <span style="color: #10b981; font-weight: 600;">{stats['total_baselines']}</span></div>
            <div>⚠️ <b>Files Changed:</b> <span style="color: {changed_color}; font-weight: 600;">{stats['changed_count']}</span></div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown(
        """
        <div style="font-size: 0.78rem; color: #8b949e; line-height: 1.5;">
            <b style="color: #f0f6fc;">🔒 Privacy Guarantee:</b><br/>
            Files are checked safely on your computer. Your file contents are never executed and never uploaded to outside servers.
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================================
# PAGE 1: FILE SAFETY CHECK (PRIMARY USER-FRIENDLY THREAT CHECKER)
# ============================================================================

if nav_page == "🛡️ File Safety Check":
    st.markdown("# 🛡️ File Safety Check")
    st.caption("Check whether a file is safe to open, verify it hasn't changed, and see clear guidance in plain English.")

    c_upload, c_synthetic = st.columns([1.2, 0.8])

    uploaded_file = None
    target_source = None
    target_name = None

    with c_upload:
        st.markdown("#### Choose a File to Check")
        uploaded_file = st.file_uploader(
            "Select any file from your computer (never executed or run):",
            type=None,
            help="TraceGuard analyzes the file safely in local memory. It is never executed."
        )

    with c_synthetic:
        st.markdown("#### Or Try a Test Sample")
        sample_files = list(SAMPLES_DIR.glob("*")) if SAMPLES_DIR.exists() else []
        sample_names = ["-- Select a Test Sample --"] + [f.name for f in sample_files]

        selected_sample_name = st.selectbox(
            "Choose a test file to see how warnings are displayed:",
            sample_names
        )

    # Determine input source
    if uploaded_file is not None:
        target_source = uploaded_file
        target_name = uploaded_file.name
    elif selected_sample_name and selected_sample_name != "-- Select a Test Sample --":
        sample_path = SAMPLES_DIR / selected_sample_name
        if sample_path.exists():
            target_source = sample_path
            target_name = sample_path.name

    if target_source is not None:
        with st.spinner("Checking file safety, verifying structure, and checking trusted records..."):
            # 1. Non-invasive file analysis
            analysis = analyze_file(target_source, filename=target_name)

            # 2. Query baseline for match
            baseline_match = get_baseline_by_identifier(analysis["file_name"], DEFAULT_DB_PATH)
            if not baseline_match:
                baseline_match_hash = get_baseline_by_hash(analysis["sha256"], DEFAULT_DB_PATH)
                if baseline_match_hash:
                    baseline_match = baseline_match_hash

            if baseline_match:
                baseline_id = baseline_match["id"]
                baseline_hash = baseline_match["sha256_hash"]
                diff_data = compare_hashes(analysis["sha256"], baseline_hash)
                integrity_status = diff_data["status"]
            else:
                baseline_id = None
                baseline_hash = None
                integrity_status = "UNKNOWN"

            # 3. Evaluate explainable rules & risk score
            findings = evaluate_rules(analysis)
            risk_result = calculate_risk_score(findings)
            risk_score = risk_result["risk_score"]
            risk_level = risk_result["risk_level"]

            # 4. Formulate recommendation & user-friendly verdict
            recommendation = determine_recommendation(
                risk_score=risk_score,
                risk_level=risk_level,
                integrity_status=integrity_status,
                findings=findings,
                file_size=analysis["file_size"],
                primary_ext=analysis["primary_extension"]
            )

            # 5. Persist scan to SQLite
            scan_id = record_scan(
                file_name=analysis["file_name"],
                sha256_hash=analysis["sha256"],
                sha1_hash=analysis["sha1"],
                md5_hash=analysis["md5"],
                file_size=analysis["file_size"],
                detected_mime=analysis["mime_type"],
                file_extension=analysis["primary_extension"],
                entropy=analysis["entropy"],
                risk_score=risk_score,
                risk_level=risk_level,
                integrity_status=integrity_status,
                baseline_id=baseline_id,
                baseline_hash=baseline_hash,
                findings=findings,
                recommendation=recommendation,
                db_path=DEFAULT_DB_PATH
            )

            st.session_state["latest_scan_id"] = scan_id

        # -----------------------------------------------------------------
        # SIMPLE, USER-FRIENDLY RESULTS PRESENTATION
        # -----------------------------------------------------------------
        st.markdown("---")

        # 1. File Name and Size Header
        col_hdr1, col_hdr2 = st.columns([2, 1])
        with col_hdr1:
            st.markdown(f"**File name:**\n### 📄 {analysis['file_name']}")
        with col_hdr2:
            st.markdown(f"**File size:**\n### ⚖️ {analysis['file_size_formatted']}")

        verdict = recommendation.get("verdict", VERDICT_UNABLE_TO_DETERMINE)
        verdict_color = recommendation.get("verdict_color", "#94a3b8")

        # 2. Large Verdict Card
        v_low = str(verdict).lower()
        if "safe" in v_low or "no significant" in v_low:
            verdict_css = "verdict-safe"
            verdict_heading = "### 🟢 NO SIGNIFICANT WARNING SIGNS DETECTED"
            verdict_summary = recommendation.get("summary", "No known warning signs were detected in this file.")
        elif "high" in v_low or "malicious" in v_low:
            verdict_css = "verdict-malicious"
            verdict_heading = "### 🔴 HIGH RISK"
            verdict_summary = recommendation.get("summary", "Strong signs of a potentially harmful file were detected. Do not open or execute it.")
        elif "unable" in v_low or "insufficient" in v_low:
            verdict_css = "verdict-undetermined"
            verdict_heading = "### ⚪ UNABLE TO DETERMINE"
            verdict_summary = recommendation.get("summary", "Insufficient information to assess the file.")
        else: # Needs review / Suspicious
            verdict_css = "verdict-suspicious"
            verdict_heading = "### 🟡 NEEDS REVIEW"
            verdict_summary = recommendation.get("summary", "Unusual characteristics or warning signs were detected. Review the file before opening.")

        st.markdown(
            f"""
            <div class="verdict-card {verdict_css}">
                <div style="font-size: 1.5rem; font-weight: 700; margin-bottom: 6px;">
                    {verdict_heading.replace('### ', '')}
                </div>
                <div style="font-size: 1.05rem; color: #f0f6fc; line-height: 1.5; margin-bottom: 8px;">
                    {verdict_summary}
                </div>
                <div style="font-size: 0.90rem; color: #8b949e; line-height: 1.5;">
                    {recommendation.get('disclaimer', '')}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 3. Risk Level and Risk Score
        col_risk1, col_risk2 = st.columns(2)
        with col_risk1:
            st.markdown(f"### Risk Level: {risk_level}")
            if integrity_status == "CHANGED":
                if risk_score < 20:
                    st.markdown("*⚠️ No malicious content detected, but file differs from its trusted baseline.*")
                else:
                    st.markdown(f"*⚠️ {RISK_LEVEL_DESCRIPTIONS.get(risk_level, '')} and file differs from trusted baseline.*")
            else:
                st.markdown(f"*{RISK_LEVEL_DESCRIPTIONS.get(risk_level, recommendation.get('summary', ''))}*")

        with col_risk2:
            st.markdown(f"### Risk Score: {risk_score} / 100")
            st.markdown(
                f"""
                <div style="font-size: 0.88rem; color: #38bdf8; line-height: 1.45;">
                    ℹ️ <i>{recommendation.get('score_meaning')}</i>
                </div>
                """,
                unsafe_allow_html=True
            )

        # 4. File Identity (Replacing raw hashes)
        st.markdown(
            """
            <div style="background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; margin: 18px 0 14px 0;">
                <h4 style="margin: 0 0 6px 0; color: #00e5ff;">🔑 File Identity</h4>
                <p style="margin: 0; color: #c9d1d9; font-size: 0.95rem; line-height: 1.5;">
                    This file has a unique digital fingerprint. If someone changes even one letter in the file, this fingerprint will change.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 5. Trusted File Protection
        st.markdown("### 🛡️ Trusted File Protection")
        st.markdown("**Have you saved this file before?**")

        if integrity_status == "UNCHANGED":
            st.success("✅ **File Has Not Changed** — Matches the version you saved earlier.")
        elif integrity_status == "CHANGED":
            st.error("⚠️ **File Has Changed** — This file is different from the version you saved earlier.")
            st.info("If this change was expected (for example, you edited and re-saved the document), you can save this new version as your trusted copy.")

            confirm_up = st.checkbox("I know this file was intentionally updated and want to save this new version as my trusted file.", key="chk_up")
            if st.button("Update Trusted Version", disabled=not confirm_up, type="primary"):
                update_baseline(
                    baseline_id=baseline_id,
                    new_sha256_hash=analysis["sha256"],
                    new_file_size=analysis["file_size"],
                    new_entropy=analysis["entropy"],
                    notes_append="Updated by user in File Safety Check",
                    db_path=DEFAULT_DB_PATH
                )
                st.success("Trusted file version updated successfully!")
                st.rerun()
        else: # UNKNOWN
            st.info("ℹ️ **No Saved Trusted Version** — You can save this file as a trusted version if you trust it.")
            if st.button("Save as Trusted Version", type="primary"):
                try:
                    register_baseline(
                        identifier=analysis["file_name"],
                        file_name=analysis["file_name"],
                        sha256_hash=analysis["sha256"],
                        file_size=analysis["file_size"],
                        file_type=analysis["primary_extension"],
                        entropy=analysis["entropy"],
                        trusted_notes="Saved by user in File Safety Check",
                        db_path=DEFAULT_DB_PATH
                    )
                    st.success(f"Saved '{analysis['file_name']}' as a trusted version!")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

        # 6. What did we find?
        st.markdown("### 🔍 What did we find?")

        if not findings:
            st.markdown(
                """
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 8px; padding: 18px 20px; color: #10b981; margin-bottom: 18px;">
                    <div style="font-weight: 700; font-size: 1.05rem; margin-bottom: 4px;">✅ No warning signs detected</div>
                    <div style="color: #c9d1d9; font-size: 0.93rem;">
                        This file looks normal based on the checks performed. The file name, internal format, and content structure match standard expectations.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            for f in findings:
                sev = f.get("severity", "MEDIUM").lower()
                title = f.get("friendly_title", f.get("name", "Warning detected"))
                if not title.startswith(("⚠️", "🚨", "ℹ️", "🟢")):
                    icon = "🚨" if sev == "critical" else ("⚠️" if sev in ["high", "medium"] else "ℹ️")
                    title = f"{icon} {title}"

                explanation = f.get("simple_explanation", f.get("evidence", ""))
                action = f.get("recommended_action", "")

                st.markdown(
                    f"""
                    <div class="finding-card finding-card-{sev}">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span style="font-weight: 700; font-size: 1.05rem; color: #f0f6fc;">
                                {title}
                            </span>
                            <div>
                                {render_risk_badge(f.get('severity', 'MEDIUM'))}
                            </div>
                        </div>
                        <div style="font-size: 0.93rem; color: #f0f6fc; margin-bottom: 8px; line-height: 1.55;">
                            <b>Simple explanation:</b> {explanation}
                        </div>
                        <div style="font-size: 0.88rem; color: #38bdf8; background: #0d1117; padding: 8px 12px; border-radius: 6px; border: 1px solid #30363d;">
                            <b>Advice:</b> {action}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        # 7. What should I do?
        st.markdown("### 📋 What should I do?")
        st.markdown("#### Recommended Action")

        rec_actions = recommendation.get("recommended_actions", [])
        if not rec_actions:
            rec_actions = [
                "If you know and trust the sender, confirm that this is the expected file.",
                "If you do not recognize the sender, do not open the file.",
                "If this file is important, scan it using your organization's approved antivirus/security scanner.",
                "If multiple warnings appear, ask a security professional to investigate it."
            ]

        for act in rec_actions:
            st.markdown(f"- {act}")

        # -----------------------------------------------------------------
        # DOWNLOAD SCAN REPORT
        # -----------------------------------------------------------------
        scan_payload = {
            "id": scan_id,
            "file_name": analysis["file_name"],
            "file_size": analysis["file_size"],
            "file_size_formatted": analysis.get("file_size_formatted"),
            "file_extension": analysis["primary_extension"],
            "detected_mime": analysis["mime_type"],
            "entropy": analysis["entropy"],
            "entropy_interpretation": analysis.get("entropy_interpretation"),
            "sha256_hash": analysis["sha256"],
            "sha1_hash": analysis["sha1"],
            "md5_hash": analysis["md5"],
            "integrity_status": integrity_status,
            "baseline_id": baseline_id,
            "baseline_hash": baseline_hash,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings,
            "recommendation": recommendation,
            "scanned_at": analysis.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
        }
        report_text = generate_text_report(scan_payload)
        safe_fname = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', Path(analysis["file_name"]).stem) or "file"
        report_download_filename = f"TRACEGUARD_Report_{safe_fname}.txt"

        col_dl_a, col_dl_b = st.columns([1, 1])
        with col_dl_a:
            st.download_button(
                label="📥 Download Scan Report",
                data=report_text,
                file_name=report_download_filename,
                mime="text/plain",
                help="Download a clean, plain-text threat investigation report with verification details and recommendations.",
                type="primary",
                width="stretch"
            )
        with col_dl_b:
            st.download_button(
                label="📦 Download JSON Report",
                data=generate_json_report(scan_payload),
                file_name=f"TRACEGUARD_Report_{safe_fname}.json",
                mime="application/json",
                help="Download structured JSON report data for integration and security logs.",
                width="stretch"
            )

        # -----------------------------------------------------------------
        # SECONDARY ADVANCED SECTION: TECHNICAL REPORT
        # -----------------------------------------------------------------
        with st.expander("🛠️ Technical Report (Optional for Security Specialists)", expanded=False):
            st.caption("Technical forensic telemetry for incident responders, IT administrators, and security specialists.")

            t_sub_a, t_sub_b, t_sub_c, t_sub_d, t_sub_e, t_sub_f, t_sub_g = st.tabs([
                "🔐 Fingerprints",
                "📑 Signatures & Header",
                "📊 Shannon Entropy",
                f"⚖️ Detection Rules ({len(findings)})",
                "🔤 Filename Diagnostics",
                "🛡️ Baseline Record",
                "ℹ️ Database Details"
            ])

            # A. Cryptographic Fingerprints
            with t_sub_a:
                st.markdown("#### Cryptographic Fingerprints")
                st.caption("Hashes computed via non-invasive 64 KB chunked streaming.")

                st.markdown("**SHA-256 (Primary Integrity Fingerprint):**")
                st.code(analysis["sha256"], language="text")
                st.markdown(
                    """
                    <div style="font-size: 0.85rem; color: #8b949e; margin-bottom: 14px;">
                        <b>Purpose & Limitations:</b> SHA-256 mathematically confirms whether a file has changed.
                        However, a SHA-256 hash proves <i>data integrity</i>, not legitimacy on its own.
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                col_ha, col_hb = st.columns(2)
                with col_ha:
                    st.markdown("**SHA-1 (Legacy):**")
                    st.code(analysis["sha1"], language="text")
                with col_hb:
                    st.markdown("**MD5 (Legacy Checksum):**")
                    st.code(analysis["md5"], language="text")

            # B. Signatures & Format
            with t_sub_b:
                st.markdown("#### File Signature & Header Analysis")
                col_b1, col_b2 = st.columns(2)
                with col_b1:
                    sig = analysis.get("detected_signature")
                    if sig:
                        st.success(f"**Identified Magic Signature:** {sig['name']} (`{sig['id']}`)")
                        st.markdown(f"- **MIME Type:** `{sig['mime']}`")
                        st.markdown(f"- **Expected Extensions:** `{', '.join(sig['expected_extensions'])}`")
                    else:
                        st.warning("No standard signature match in header catalog.")

                    st.markdown(f"**Detected MIME:** `{analysis['mime_type']}`")
                    st.markdown(f"**Primary Extension:** `{analysis['primary_extension'] or '(none)'}`")

                with col_b2:
                    st.markdown("**Header Raw Hexadecimal Dump (First 32 bytes):**")
                    st.code(analysis["header_hex"] or "(empty file)", language="text")
                    st.markdown("**Header ASCII Representation:**")
                    st.code(analysis["header_ascii"] or "(empty file)", language="text")

            # C. Shannon Entropy
            with t_sub_c:
                st.markdown("#### Shannon Entropy & Structural Metrics")
                st.caption("Entropy measures byte randomness on a scale from 0.000 to 8.000.")

                col_c1, col_c2 = st.columns([1, 1])
                with col_c1:
                    st.metric("Measured Shannon Entropy", f"{analysis['entropy']:.4f} / 8.0000")
                    st.markdown(f"**Technical Interpretation:** {analysis['entropy_interpretation']}")
                    st.markdown(
                        """
                        <div style="font-size: 0.85rem; color: #8b949e; margin-top: 10px; line-height: 1.5;">
                            <b>File Type Context:</b> Compressed files (ZIP, GZ), encrypted archives, and modern images naturally have high entropy (&ge; 7.45).
                            High entropy alone does NOT prove a file contains malware.
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                with col_c2:
                    fig_gauge = go.Figure(
                        go.Indicator(
                            mode="gauge+number",
                            value=analysis["entropy"],
                            domain={'x': [0, 1], 'y': [0, 1]},
                            gauge={
                                'axis': {'range': [0, 8], 'tickwidth': 1, 'tickcolor': "#8b949e"},
                                'bar': {'color': "#00e5ff"},
                                'bgcolor': "#161b22",
                                'steps': [
                                    {'range': [0, 4.0], 'color': '#10b981'},
                                    {'range': [4.0, 7.2], 'color': '#38bdf8'},
                                    {'range': [7.2, 7.5], 'color': '#f59e0b'},
                                    {'range': [7.5, 8.0], 'color': '#ef4444'}
                                ],
                            }
                        )
                    )
                    fig_gauge.update_layout(
                        paper_bgcolor="#161b22",
                        height=220,
                        margin=dict(t=20, b=20, l=20, r=20),
                        font=dict(color="#f0f6fc")
                    )
                    st.plotly_chart(
                        fig_gauge,
                        width="stretch",
                        config={"displayModeBar": False, "staticPlot": True, "showTips": False, "responsive": True}
                    )

            # D. Detection Rules & Rule IDs
            with t_sub_d:
                st.markdown("#### Rule-Based Detection Engine Findings")
                if not findings:
                    st.info("No rule heuristics triggered for this sample.")
                else:
                    for f in findings:
                        st.markdown(f"##### [{f['rule_id']}] {f['name']}")
                        col_rfa, col_rfb = st.columns(2)
                        with col_rfa:
                            st.write(f"- **Severity:** `{f['severity']}`")
                            st.write(f"- **Category:** `{f.get('category', 'structural')}`")
                            st.write(f"- **Score Contribution:** `+{f.get('points', 0)} pts`")
                        with col_rfb:
                            st.write(f"- **Observed Evidence:** {f['evidence']}")
                            st.write(f"- **Limitations:** {f.get('limitations', 'Standard heuristic limitation.')}")
                        st.markdown("---")

                st.markdown("##### Category Caps Breakdown")
                st.dataframe(pd.DataFrame(risk_result["breakdown"]), width="stretch", hide_index=True)

            # E. Filename Diagnostics
            with t_sub_e:
                st.markdown("#### Filename Anomaly Diagnostics")
                anom = analysis.get("filename_anomalies", {})
                col_ea, col_eb = st.columns(2)
                with col_ea:
                    st.write(f"- **Suffix Count:** `{anom.get('suffix_count')}`")
                    st.write(f"- **Detected Suffixes:** `{anom.get('all_suffixes')}`")
                    st.write(f"- **Double Extension Detected:** `{anom.get('is_double_extension')}`")
                with col_eb:
                    st.write(f"- **Bidirectional / RTLO Characters:** `{anom.get('has_spoof_chars')}`")
                    if anom.get("has_spoof_chars"):
                        st.json(anom.get("spoof_chars"))
                    st.write(f"- **Trailing Spaces:** `{anom.get('has_trailing_space')}`")
                    st.write(f"- **Trailing Dots:** `{anom.get('has_trailing_dot')}`")

            # F. Baseline Record
            with t_sub_f:
                st.markdown("#### Trusted Baseline Technical Record")
                if baseline_match:
                    st.write(f"- **Baseline ID:** `#{baseline_id}`")
                    st.write(f"- **Registered Identifier:** `{baseline_match['identifier']}`")
                    st.write(f"- **Baseline SHA-256:** `{baseline_hash}`")
                    st.write(f"- **Registered At:** `{baseline_match['created_at']}`")
                    if integrity_status == "CHANGED":
                        st.markdown("**Fingerprint Difference Highlight:**")
                        st.markdown(render_hash_diff_html(analysis["sha256"], baseline_hash), unsafe_allow_html=True)
                else:
                    st.info("No baseline record exists in SQLite for this file.")

            # G. Database Details
            with t_sub_g:
                st.markdown("#### Scan & Audit Details")
                st.write(f"- **Scan Record ID:** `#{scan_id}`")
                st.write(f"- **Timestamp (UTC):** `{analysis['timestamp']}`")
                st.write(f"- **Database Path:** `{DEFAULT_DB_PATH}`")
    else:
        st.markdown(
            """
            <div style="background: #161b22; border: 2px dashed #30363d; border-radius: 12px; padding: 60px 40px; text-align: center; margin-top: 30px;">
                <div style="font-size: 3rem; margin-bottom: 12px;">🛡️</div>
                <h3 style="color: #f0f6fc; margin-bottom: 8px;">Ready to Check File</h3>
                <p style="color: #8b949e; max-width: 600px; margin: 0 auto 20px auto; font-size: 0.95rem; line-height: 1.6;">
                    Upload any file from your computer using the file selector above, or choose an example test case to see how TRACEGUARD AI identifies potential warnings.
                </p>
                <div style="display: inline-flex; gap: 15px; font-size: 0.85rem; color: #00e5ff;">
                    <span>⚡ Plain-Language Verdict</span>
                    <span>•</span>
                    <span>🔑 File Identity</span>
                    <span>•</span>
                    <span>🛡️ Trusted Protection</span>
                    <span>•</span>
                    <span>📋 Clear Advice</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


# ============================================================================
# PAGE 2: PROTECTION OVERVIEW (SECURITY DASHBOARD)
# ============================================================================

elif nav_page == "📊 Protection Overview":
    st.markdown("# 📊 Protection Overview")
    st.caption("Summary of files checked, changes detected, and overall safety status.")

    stats = get_scan_stats(DEFAULT_DB_PATH)

    # 4 Top KPI Cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{stats['total_scans']}</div>
                <div class="metric-label">Total Files Checked</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        changed_color = "#ef4444" if stats['changed_count'] > 0 else "#00e5ff"
        st.markdown(
            f"""
            <div class="metric-card" style="border-left: 3px solid {changed_color};">
                <div class="metric-value" style="color: {changed_color};">{stats['changed_count']}</div>
                <div class="metric-label">Files Changed</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:
        inv_color = "#f97316" if stats['investigation_required'] > 0 else "#00e5ff"
        st.markdown(
            f"""
            <div class="metric-card" style="border-left: 3px solid {inv_color};">
                <div class="metric-value" style="color: {inv_color};">{stats['investigation_required']}</div>
                <div class="metric-label">Files Needing Attention</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            f"""
            <div class="metric-card" style="border-left: 3px solid #10b981;">
                <div class="metric-value" style="color: #10b981;">{stats['unchanged_count']}</div>
                <div class="metric-label">Verified Unchanged</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("### Safety Status Breakdown")
    c_left, c_right = st.columns([1, 1])

    with c_left:
        r_counts = stats["risk_counts"]
        labels = ["Safe", "Low Risk", "Medium Risk", "High Risk", "Critical Risk"]
        key_map = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        values = [r_counts.get(k, 0) for k in key_map]
        colors = ["#10b981", "#38bdf8", "#f59e0b", "#f97316", "#ef4444"]

        if sum(values) == 0:
            st.info("No files checked yet. Check a file in '🛡️ File Safety Check' to populate charts.")
        else:
            fig_risk = go.Figure(
                data=[
                    go.Pie(
                        labels=labels,
                        values=values,
                        hole=0.55,
                        marker=dict(colors=colors),
                        textinfo="label+value",
                        hoverinfo="label+value+percent"
                    )
                ]
            )
            fig_risk.update_layout(
                title="Risk Level Breakdown",
                template="plotly_dark",
                paper_bgcolor="#161b22",
                plot_bgcolor="#161b22",
                margin=dict(t=40, b=20, l=20, r=20),
                height=300,
                showlegend=False,
            )
            st.plotly_chart(
                fig_risk,
                width="stretch",
                config={"displayModeBar": False, "showTips": False, "responsive": True}
            )

    with c_right:
        stat_labels = ["Unchanged", "Changed", "Not Saved"]
        stat_values = [
            stats["unchanged_count"],
            stats["changed_count"],
            stats["unknown_count"]
        ]
        stat_colors = ["#10b981", "#ef4444", "#94a3b8"]

        if sum(stat_values) == 0:
            st.info("No trusted file comparisons available yet.")
        else:
            fig_stat = go.Figure(
                data=[
                    go.Bar(
                        x=stat_labels,
                        y=stat_values,
                        marker=dict(color=stat_colors),
                        text=stat_values,
                        textposition="auto"
                    )
                ]
            )
            fig_stat.update_layout(
                title="Trusted File Statuses",
                template="plotly_dark",
                paper_bgcolor="#161b22",
                plot_bgcolor="#161b22",
                margin=dict(t=40, b=20, l=20, r=20),
                height=300,
                yaxis=dict(title="File Count", gridcolor="#30363d"),
                xaxis=dict(gridcolor="#30363d")
            )
            st.plotly_chart(
                fig_stat,
                width="stretch",
                config={"displayModeBar": False, "showTips": False, "responsive": True}
            )

    st.markdown("### Recent Check Activity")
    recent = stats.get("recent_scans", [])
    if recent:
        df_recent = pd.DataFrame(recent)
        df_display = pd.DataFrame({
            "Check ID": df_recent["id"],
            "Date & Time": df_recent["scanned_at"].apply(lambda s: s[:19].replace("T", " ") if s else "N/A"),
            "File Name": df_recent["file_name"],
            "Risk Score": df_recent["risk_score"].apply(lambda score: f"{score}/100"),
            "Risk Level": df_recent["risk_level"],
            "Trusted Status": df_recent["integrity_status"].apply(lambda s: "⚠️ CHANGED" if s == "CHANGED" else ("✅ UNCHANGED" if s == "UNCHANGED" else "ℹ️ UNKNOWN"))
        })
        st.dataframe(df_display, width="stretch", hide_index=True)
    else:
        st.markdown(
            """
            <div style="background: #161b22; border: 1px dashed #30363d; border-radius: 8px; padding: 30px; text-align: center; color: #8b949e;">
                <p style="font-size: 1.1rem; margin-bottom: 8px;">No recent check activity.</p>
                <p style="font-size: 0.85rem;">Go to <b>🛡️ File Safety Check</b> to check your first file.</p>
            </div>
            """,
            unsafe_allow_html=True
        )


# ============================================================================
# PAGE 3: TRUSTED FILES (BASELINE REGISTRY & COMPARISON)
# ============================================================================

elif nav_page == "📁 Trusted Files":
    st.markdown("# 📁 Trusted Files & Verification")
    st.caption("Keep track of verified, trusted versions of your files to quickly catch unauthorized changes.")

    tab_baselines, tab_compare = st.tabs(["📋 Saved Trusted Files", "🔬 Compare Two Fingerprints"])

    with tab_baselines:
        st.markdown("#### Saved Trusted Files")
        st.caption("Manage saved versions of your trusted files. TRACEGUARD AI will alert you if any of these files are modified.")

        b_search = st.text_input("Search Saved Files (by filename or note):", key="search_baselines")
        all_b = list_baselines(search_query=b_search, db_path=DEFAULT_DB_PATH)

        if all_b:
            df_b = pd.DataFrame(all_b)
            df_b_view = pd.DataFrame({
                "ID": df_b["id"],
                "File Name": df_b["file_name"],
                "Size (Bytes)": df_b["file_size"],
                "Date Saved": df_b["updated_at"].apply(lambda s: s[:19].replace("T", " ") if s else ""),
                "Notes": df_b["trusted_notes"]
            })
            st.dataframe(df_b_view, width="stretch", hide_index=True)

            st.markdown("---")
            st.markdown("##### Remove a Trusted File")
            sel_b_id = st.selectbox(
                "Select File to Remove:",
                [b["id"] for b in all_b],
                format_func=lambda x: f"#{x} — {next(b['file_name'] for b in all_b if b['id'] == x)}"
            )

            if st.button("Delete Selected Trusted File", type="secondary"):
                ok = delete_baseline(sel_b_id, DEFAULT_DB_PATH)
                if ok:
                    st.success(f"Trusted record #{sel_b_id} removed.")
                    st.rerun()
        else:
            st.info("No saved trusted files found. When checking a file in '🛡️ File Safety Check', click 'Save as Trusted Version' to add it here.")

        with st.expander("Manually Add a Trusted File Fingerprint"):
            m_fname = st.text_input("File Name:", key="m_fname")
            m_hash = st.text_input("Digital Fingerprint (SHA-256 Hash):", key="m_hash")
            m_notes = st.text_area("Notes (e.g. Official vendor release, clean copy):", key="m_notes")

            if st.button("Save Trusted Fingerprint", type="primary"):
                if not m_fname or not m_hash:
                    st.error("File name and digital fingerprint (hash) are required.")
                else:
                    try:
                        new_id = register_baseline(
                            identifier=m_fname,
                            file_name=m_fname,
                            sha256_hash=m_hash,
                            trusted_notes=m_notes,
                            db_path=DEFAULT_DB_PATH
                        )
                        st.success(f"Successfully saved trusted record #{new_id}!")
                        st.rerun()
                    except ValueError as err:
                        st.error(str(err))

    with tab_compare:
        st.markdown("#### Compare Two Digital Fingerprints")
        st.caption("Check whether two digital fingerprints match character-for-character to see if a file has changed.")

        c_cmp1, c_cmp2 = st.columns(2)
        with c_cmp1:
            st.markdown("**Original Fingerprint A:**")
            hash_input_a = st.text_area("Enter original SHA-256 fingerprint:", height=80, key="hash_a")
        with c_cmp2:
            st.markdown("**New Fingerprint B:**")
            hash_input_b = st.text_area("Enter new SHA-256 fingerprint:", height=80, key="hash_b")

        if hash_input_a and hash_input_b:
            res_diff = compare_hashes(hash_input_a, hash_input_b)

            if res_diff["match"]:
                st.markdown(
                    """
                    <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: 8px; padding: 16px; margin: 15px 0;">
                        <h4 style="color: #10b981; margin: 0 0 4px 0;">✅ Both Fingerprints Match</h4>
                        <p style="margin: 0; color: #f0f6fc; font-size: 0.9rem;">The fingerprints are 100% identical. The file contents have not changed.</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f"""
                    <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 16px; margin: 15px 0;">
                        <h4 style="color: #ef4444; margin: 0 0 4px 0;">⚠️ Fingerprints Do Not Match</h4>
                        <p style="margin: 0; color: #f0f6fc; font-size: 0.9rem;">
                            The fingerprints differ. The file contents have been modified.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            st.markdown(render_hash_diff_html(hash_input_b, hash_input_a), unsafe_allow_html=True)


# ============================================================================
# PAGE 4: SCAN HISTORY
# ============================================================================

elif nav_page == "📜 Scan History":
    st.markdown("# 📜 Scan History")
    st.caption("Searchable history of files checked, risk levels, and change records.")

    c_f1, c_f2, c_f3 = st.columns([1, 1, 1.5])
    with c_f1:
        risk_filter = st.selectbox("Filter by Risk Level:", ["ALL", "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with c_f2:
        integrity_filter = st.selectbox("Filter by Change Status:", ["ALL", "UNCHANGED", "CHANGED", "UNKNOWN"])
    with c_f3:
        search_query = st.text_input("Search File Name:")

    scans, total_count = get_scans(
        limit=200,
        risk_filter=risk_filter,
        integrity_filter=integrity_filter,
        search_query=search_query,
        db_path=DEFAULT_DB_PATH
    )

    st.markdown(f"**Found {total_count} matching records.**")

    if scans:
        df_scans = pd.DataFrame(scans)
        df_table = pd.DataFrame({
            "Check ID": df_scans["id"],
            "Date & Time": df_scans["scanned_at"].apply(lambda s: s[:19].replace("T", " ") if s else ""),
            "File Name": df_scans["file_name"],
            "Verdict": df_scans["recommendation"].apply(lambda r: (r.get("verdict") if isinstance(r, dict) else None) or "Unable to Determine"),
            "Size (Bytes)": df_scans["file_size"],
            "Risk Score": df_scans["risk_score"].apply(lambda s: f"{s}/100"),
            "Risk Level": df_scans["risk_level"],
            "Trusted Status": df_scans["integrity_status"].apply(lambda s: "⚠️ CHANGED" if s == "CHANGED" else ("✅ UNCHANGED" if s == "UNCHANGED" else "ℹ️ UNKNOWN")),
            "Warnings Found": df_scans["findings"].apply(lambda f: len(f) if isinstance(f, list) else 0)
        })

        st.dataframe(df_table, width="stretch", hide_index=True)

        c_exp_csv, c_clear = st.columns([1, 1])
        with c_exp_csv:
            csv_data = generate_csv_report(scans)
            st.download_button(
                label="📥 Download History to CSV",
                data=csv_data,
                file_name=f"traceguard_history_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

        st.markdown("---")
        st.markdown("#### View Details of a Previous Check")
        inspect_id = st.selectbox(
            "Select Check ID:",
            [s["id"] for s in scans],
            format_func=lambda x: f"Check #{x} — {next(s['file_name'] for s in scans if s['id'] == x)}"
        )

        selected_scan = get_scan_by_id(inspect_id, DEFAULT_DB_PATH)
        if selected_scan:
            rec = selected_scan.get("recommendation", {})
            st.markdown(f"**Verdict:** {render_verdict_badge(rec.get('verdict', 'Unable to Determine'))} &nbsp; {render_integrity_badge(selected_scan['integrity_status'])}", unsafe_allow_html=True)
            change_note = " &nbsp; <span style='color: #ef4444; font-size: 0.88rem;'>⚠️ (File differs from trusted baseline)</span>" if selected_scan.get("integrity_status") == "CHANGED" else ""
            st.markdown(f"**Risk Score:** {selected_scan['risk_score']}/100 ({render_risk_badge(selected_scan['risk_level'])}){change_note}", unsafe_allow_html=True)

            findings = selected_scan.get("findings", [])
            if findings:
                st.markdown("**Warnings Detected:**")
                for f in findings:
                    title = f.get("friendly_title", f.get("name", "Warning"))
                    st.markdown(f"- **{title}** (`{f.get('severity')}`): {f.get('simple_explanation', f.get('evidence'))}")
            else:
                st.markdown("*No warnings detected.*")

            if rec:
                st.markdown(f"**Summary:** {rec.get('summary', '')}")
    else:
        st.info("No records match your selected filters.")

    st.markdown("---")
    with st.expander("Danger Zone: Clear Scan History"):
        st.warning("This will remove all historical check records. Saved trusted files will be preserved.")
        if st.button("Permanently Clear History", type="secondary"):
            clear_history(DEFAULT_DB_PATH)
            st.success("History cleared.")
            st.rerun()


# ============================================================================
# PAGE 5: DOWNLOAD REPORTS
# ============================================================================

elif nav_page == "📄 Download Reports":
    st.markdown("# 📄 Download Reports")
    st.caption("Download clean, shareable summary reports for your records or to share with IT/security specialists.")

    scans, total = get_scans(limit=100, db_path=DEFAULT_DB_PATH)

    if not scans:
        st.warning("No files have been checked yet. Check a file in '🛡️ File Safety Check' first.")
    else:
        default_index = 0
        if "latest_scan_id" in st.session_state:
            for idx, s in enumerate(scans):
                if s["id"] == st.session_state["latest_scan_id"]:
                    default_index = idx
                    break

        selected_scan_id = st.selectbox(
            "Select File Check to Report On:",
            [s["id"] for s in scans],
            index=default_index,
            format_func=lambda x: f"Check #{x} — {next(s['file_name'] for s in scans if s['id'] == x)} ({next(s['scanned_at'][:19] for s in scans if s['id'] == x)})"
        )

        scan_record = get_scan_by_id(selected_scan_id, DEFAULT_DB_PATH)

        if scan_record:
            json_report = generate_json_report(scan_record)
            csv_report = generate_csv_report([scan_record])
            md_report = generate_markdown_summary(scan_record)

            col_d1, col_d2, col_d3 = st.columns(3)
            with col_d1:
                st.download_button(
                    label="📥 Download JSON Report (.json)",
                    data=json_report,
                    file_name=f"traceguard_report_{scan_record['file_name']}_{scan_record['id']}.json",
                    mime="application/json",
                    type="primary"
                )
            with col_d2:
                st.download_button(
                    label="📥 Download CSV Report (.csv)",
                    data=csv_report,
                    file_name=f"traceguard_report_{scan_record['file_name']}_{scan_record['id']}.csv",
                    mime="text/csv"
                )
            with col_d3:
                st.download_button(
                    label="📥 Download Markdown Summary (.md)",
                    data=md_report,
                    file_name=f"traceguard_summary_{scan_record['file_name']}_{scan_record['id']}.md",
                    mime="text/markdown"
                )

            st.markdown("---")
            st.markdown("### Report Preview")
            r_tab1, r_tab2, r_tab3 = st.tabs(["📄 Formatted Summary", "⚙️ JSON Structure", "📊 CSV Raw"])
            with r_tab1:
                st.markdown(md_report)
            with r_tab2:
                st.json(json_report)
            with r_tab3:
                st.code(csv_report, language="csv")


# ============================================================================
# PAGE 6: ABOUT
# ============================================================================

elif nav_page == "ℹ️ About":
    st.markdown(f"# ℹ️ About {APP_NAME}")
    st.markdown(f"### *{TAGLINE}*")
    st.caption(f"User-Friendly File Threat Checker (Version {VERSION})")

    st.markdown(
        """
        ### What is TRACEGUARD AI?
        **TRACEGUARD AI** is a user-friendly file threat checker designed to answer five simple questions for everyday users:

        1. **Is this file okay?**
        2. **Is something suspicious?**
        3. **What was detected?**
        4. **How serious is it?**
        5. **What should I do?**

        Behind the scenes, TRACEGUARD AI inspects file headers, verifies extensions, checks for disguise techniques, and creates digital fingerprints to detect unauthorized changes.
        """
    )

    st.markdown("---")
    st.markdown("### Safety Categories")
    st.markdown(
        """
        | Category | Meaning |
        |---|---|
        | 🟢 **No significant warning signs detected** | Static checks did not detect known indicators of risk. *(Not an absolute guarantee of safety).* |
        | 🟡 **Needs review** | Unusual characteristics or warning signs were detected. Review the file before opening. |
        | 🔴 **High risk** | Strong evidence of potentially harmful content or intentional disguise was detected. Do not open or execute. |
        | ⚪ **Unable to determine** | Insufficient information to assess the file (for example, the file is empty or corrupted). |
        """
    )

    st.markdown("---")
    st.markdown("### Warning Signs Checked by TRACEGUARD AI")
    rules_table = pd.DataFrame([
        {
            "Warning": "Disguised file type",
            "What It Checks": "Detects files ending in an executable extension (.exe, .scr, .bat) preceded by a document decoy (.pdf, .docx)."
        },
        {
            "Warning": "Hidden or tricky characters in filename",
            "What It Checks": "Detects hidden characters (such as Right-to-Left Override) used to visually reverse filenames."
        },
        {
            "Warning": "Program disguised as a normal document",
            "What It Checks": "Identifies executable programs masquerading under document or image extensions."
        },
        {
            "Warning": "File type does not match its extension",
            "What It Checks": "Checks whether the internal file header matches the declared file extension."
        },
        {
            "Warning": "Unusual file content detected",
            "What It Checks": "Identifies content that looks unusually random, which can indicate compressed, encrypted, or packed content."
        },
        {
            "Warning": "Script file that can run commands",
            "What It Checks": "Flags standalone script files (.ps1, .vbs, .bat) that can execute commands on your computer."
        },
        {
            "Warning": "Unusual spaces or dots at the end of the filename",
            "What It Checks": "Detects trailing spaces or dots that can be used to bypass filename filters."
        },
        {
            "Warning": "Empty file (0 bytes)",
            "What It Checks": "Identifies 0-byte files that have no content."
        },
        {
            "Warning": "Missing normal file header",
            "What It Checks": "Detects files that are missing standard header signatures for their format."
        }
    ])
    st.dataframe(rules_table, width="stretch", hide_index=True)

    st.markdown("---")
    st.markdown("### Crucial Security & Privacy Disclaimers")
    st.markdown(
        """
        > [!IMPORTANT]
        > **1. Risk Score vs Malware Probability:**
        > A score of 25/100 means 25 points on an additive warning sign scale. It is **NOT** a 25% chance of malware.
        > TRACEGUARD AI does not fabricate statistical probabilities.

        > [!IMPORTANT]
        > **2. Digital Fingerprints and Trust:**
        > A digital fingerprint (SHA-256 hash) proves whether file content has changed.
        > However, a fingerprint proves *data integrity*, not whether the author is trustworthy. Always ensure you trust the origin of the file.

        > [!WARNING]
        > **3. Heuristics are not an Antivirus Replacement:**
        > TRACEGUARD AI checks file structure and known warning signs. It does not replace full antivirus software or endpoint security tools.

        > [!TIP]
        > **4. Strict Zero-Execution Policy & Offline Privacy:**
        > Uploaded files are inspected safely in local memory. Files are **never executed**, never run, and never sent to external servers.
        """
    )
