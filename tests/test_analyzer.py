"""
Tests for traceguard.analyzer
"""

import io
from traceguard.analyzer import (
    format_bytes,
    format_hex_dump,
    identify_magic_signature,
    inspect_filename_anomalies,
    analyze_file
)


def test_format_bytes():
    assert format_bytes(500) == "500 B"
    assert "KB" in format_bytes(2048)
    assert "MB" in format_bytes(1024 * 1024 * 5)


def test_identify_magic_signature():
    # PNG
    png_hdr = b"\x89PNG\r\n\x1a\n\x00\x00"
    sig_png = identify_magic_signature(png_hdr)
    assert sig_png is not None
    assert sig_png["id"] == "PNG_IMG"
    assert sig_png["category"] == "image"

    # PDF
    pdf_hdr = b"%PDF-1.7\r\n"
    sig_pdf = identify_magic_signature(pdf_hdr)
    assert sig_pdf is not None
    assert sig_pdf["id"] == "PDF_DOC"

    # PE Executable
    pe_hdr = b"MZ\x90\x00"
    sig_pe = identify_magic_signature(pe_hdr)
    assert sig_pe is not None
    assert sig_pe["id"] == "PE_EXE"
    assert sig_pe["category"] == "executable"


def test_inspect_filename_anomalies():
    # Normal filename
    res_normal = inspect_filename_anomalies("report_q3.pdf")
    assert res_normal["is_double_extension"] is False
    assert res_normal["has_spoof_chars"] is False

    # Double extension
    res_double = inspect_filename_anomalies("statement.pdf.exe")
    assert res_double["is_double_extension"] is True
    assert res_double["all_suffixes"] == [".pdf", ".exe"]

    # Unicode RTLO
    res_rtlo = inspect_filename_anomalies("invoice_\u202Efdp.exe")
    assert res_rtlo["has_spoof_chars"] is True
    assert len(res_rtlo["spoof_chars"]) == 1


def test_analyze_file_stream():
    content = b"%PDF-1.4 test document content"
    stream = io.BytesIO(content)
    result = analyze_file(stream, filename="doc.pdf")

    assert result["file_name"] == "doc.pdf"
    assert result["file_size"] == len(content)
    assert len(result["sha256"]) == 64
    assert result["detected_signature"] is not None
    assert result["detected_signature"]["id"] == "PDF_DOC"
