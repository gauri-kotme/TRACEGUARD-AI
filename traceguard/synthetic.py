"""
TRACEGUARD AI - Synthetic Test Case Generator
Generates realistic, completely harmless synthetic test files for verifying:
- Baseline integrity matching (unchanged files)
- Baseline tamper/update detection (modified files)
- Suspicious double extensions (e.g., invoice.pdf.exe)
- File header / extension mismatches (e.g., PE header masquerading as PNG)
- Zero-byte files
- Unicode RTLO characters in filenames
"""

from pathlib import Path
from typing import List, Dict


def generate_synthetic_samples(target_dir: Path) -> List[Dict[str, str]]:
    """
    Creates safe, inert sample files in the given directory and returns metadata list.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    generated = []

    # 1. Valid Minimal PDF
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\n0000000101 00000 n\n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
    )
    p_pdf = target_dir / "sample_clean_document.pdf"
    p_pdf.write_bytes(pdf_content)
    generated.append({
        "filename": p_pdf.name,
        "path": str(p_pdf),
        "purpose": "Clean valid PDF baseline target"
    })

    # 2. Modified PDF (Tampered version of sample 1)
    modified_pdf = pdf_content + b"\n% Tampered comment added for integrity testing\n"
    p_pdf_mod = target_dir / "sample_clean_document_modified.pdf"
    p_pdf_mod.write_bytes(modified_pdf)
    generated.append({
        "filename": p_pdf_mod.name,
        "path": str(p_pdf_mod),
        "purpose": "Modified version of clean document (demonstrates CHANGED status)"
    })

    # 3. Valid Minimal PNG Image (1x1 red pixel)
    png_content = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
        b"\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01"
        b"\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    p_png = target_dir / "sample_image.png"
    p_png.write_bytes(png_content)
    generated.append({
        "filename": p_png.name,
        "path": str(p_png),
        "purpose": "Clean PNG image with valid magic bytes"
    })

    # 4. Double Extension Masquerade (benign text labeled with .pdf.exe)
    p_double = target_dir / "invoice_march2026.pdf.exe"
    p_double.write_text("DUMMY INERT PAYLOAD - NOT AN EXECUTABLE - FOR TEST PURPOSES ONLY", encoding="utf-8")
    generated.append({
        "filename": p_double.name,
        "path": str(p_double),
        "purpose": "Suspicious double extension (invoice.pdf.exe) trigger"
    })

    # 5. Magic Byte Mismatch (MZ header claiming to be PNG)
    # Starts with 'MZ' DOS header stub bytes, completely inert harmless test
    pe_stub = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00Safe Inert PE Header Test Stub"
    p_mismatch = target_dir / "disguised_pe_as_png.png"
    p_mismatch.write_bytes(pe_stub)
    generated.append({
        "filename": p_mismatch.name,
        "path": str(p_mismatch),
        "purpose": "Signature mismatch (PE binary masked as .png image)"
    })

    # 6. Zero-Byte Empty File
    p_empty = target_dir / "empty_lockfile.dat"
    p_empty.write_bytes(b"")
    generated.append({
        "filename": p_empty.name,
        "path": str(p_empty),
        "purpose": "Zero-byte file indicator trigger"
    })

    # 7. Unicode Right-to-Left Override (RTLO) Filename
    # \u202E causes 'gpj.exe' to render visually as 'exe.jpg'
    rtlo_filename = "Quarterly_Summary_\u202Egpj.exe"
    p_rtlo = target_dir / rtlo_filename
    p_rtlo.write_text("INERT TEST FILE - RTLO SPOOFING DEMONSTRATION", encoding="utf-8")
    generated.append({
        "filename": rtlo_filename,
        "path": str(p_rtlo),
        "purpose": "Unicode Right-to-Left Override spoofing demonstration"
    })

    # 8. Standalone Script
    p_ps1 = target_dir / "backup_routine.ps1"
    p_ps1.write_text("# Safe administrative routine\nWrite-Output 'Executing routine'\n", encoding="utf-8")
    generated.append({
        "filename": p_ps1.name,
        "path": str(p_ps1),
        "purpose": "Standalone PowerShell script indicator"
    })

    return generated


if __name__ == "__main__":
    samples_dir = Path(__file__).resolve().parent.parent / "samples"
    created = generate_synthetic_samples(samples_dir)
    print(f"Generated {len(created)} test cases in {samples_dir}")
