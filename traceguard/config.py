"""
TRACEGUARD AI - Configuration & Constants
Defines theme colors, magic byte signatures, known executable extensions, and risk bands.
"""

from pathlib import Path

# Application metadata
APP_NAME = "TRACEGUARD AI"
TAGLINE = "Verify. Investigate. Trust."
VERSION = "1.0.0"

# Default SQLite database path
DEFAULT_DB_PATH = Path("traceguard.db")

# Chunk size for cryptographic streaming (64 KB)
HASH_CHUNK_SIZE = 65536

# Maximum sample size for entropy calculation and header inspection (64 KB)
SAMPLE_ANALYSIS_SIZE = 65536

# Risk level bands (0-100 scale)
RISK_LEVEL_SAFE = "SAFE"
RISK_LEVEL_LOW = "LOW"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_CRITICAL = "CRITICAL"

# User-Friendly Threat Verdict Classifications & Categories
VERDICT_LIKELY_SAFE = "No significant warning signs detected"
VERDICT_SUSPICIOUS = "Needs review"
VERDICT_LIKELY_MALICIOUS = "High risk"
VERDICT_UNABLE_TO_DETERMINE = "Unable to determine"

# Explicit Category Constants
CATEGORY_NO_WARNINGS = VERDICT_LIKELY_SAFE
CATEGORY_NEEDS_REVIEW = VERDICT_SUSPICIOUS
CATEGORY_HIGH_RISK = VERDICT_LIKELY_MALICIOUS
CATEGORY_UNABLE_TO_DETERMINE = VERDICT_UNABLE_TO_DETERMINE

RISK_THRESHOLDS = {
    RISK_LEVEL_SAFE: (0, 19),
    RISK_LEVEL_LOW: (0, 19),
    RISK_LEVEL_MEDIUM: (20, 69),
    RISK_LEVEL_HIGH: (70, 89),
    RISK_LEVEL_CRITICAL: (90, 100),
}

# Theme palette (Dark Charcoal, Electric Cyan, Neon Blue)
THEME_COLORS = {
    "background": "#0d1117",
    "card_bg": "#161b22",
    "card_border": "#30363d",
    "cyan_accent": "#00e5ff",
    "blue_accent": "#38bdf8",
    "text_primary": "#f0f6fc",
    "text_muted": "#8b949e",
    "risk_safe": "#10b981",       # Emerald
    "risk_low": "#38bdf8",        # Light Blue
    "risk_medium": "#f59e0b",     # Amber
    "risk_high": "#f97316",       # Orange
    "risk_critical": "#ef4444",   # Coral Red
    "status_unchanged": "#10b981",
    "status_changed": "#ef4444",
    "status_unknown": "#94a3b8",
    "verdict_safe": "#10b981",
    "verdict_suspicious": "#f59e0b",
    "verdict_malicious": "#ef4444",
    "verdict_undetermined": "#94a3b8",
}

# Known executable / script extensions commonly abused in evasion
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".msi", ".msp", ".hta", ".cpl",
    ".com", ".pif", ".jar", ".app", ".bin", ".elf", ".sh"
}

# Known benign decoy primary extensions used in double-extension attacks
BENIGN_DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".rtf",
    ".zip", ".csv", ".mp3", ".mp4", ".wav"
}

# Supported file magic signatures: (magic_bytes, description, expected_extensions)
# Magic signatures are checked from the first few bytes of the file.
MAGIC_SIGNATURES = [
    {
        "id": "PE_EXE",
        "name": "Windows PE Executable / DLL",
        "magic": b"MZ",
        "offset": 0,
        "extensions": [".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi"],
        "mime": "application/x-dosexec",
        "category": "executable"
    },
    {
        "id": "ELF_EXE",
        "name": "Linux / Unix ELF Executable",
        "magic": b"\x7fELF",
        "offset": 0,
        "extensions": [".elf", ".bin", ""],
        "mime": "application/x-executable",
        "category": "executable"
    },
    {
        "id": "MACHO_32",
        "name": "Mach-O 32-bit Executable",
        "magic": b"\xfe\xed\xfa\xce",
        "offset": 0,
        "extensions": [""],
        "mime": "application/x-mach-binary",
        "category": "executable"
    },
    {
        "id": "MACHO_64",
        "name": "Mach-O 64-bit Executable",
        "magic": b"\xfe\xed\xfa\xcf",
        "offset": 0,
        "extensions": [""],
        "mime": "application/x-mach-binary",
        "category": "executable"
    },
    {
        "id": "MACHO_FAT",
        "name": "Mach-O Universal Binary",
        "magic": b"\xca\xfe\xba\xbe",
        "offset": 0,
        "extensions": [".class", ""],
        "mime": "application/x-mach-binary",
        "category": "executable"
    },
    {
        "id": "PDF_DOC",
        "name": "Adobe Portable Document Format (PDF)",
        "magic": b"%PDF-",
        "offset": 0,
        "extensions": [".pdf"],
        "mime": "application/pdf",
        "category": "document"
    },
    {
        "id": "PNG_IMG",
        "name": "Portable Network Graphics (PNG)",
        "magic": b"\x89PNG\r\n\x1a\n",
        "offset": 0,
        "extensions": [".png"],
        "mime": "image/png",
        "category": "image"
    },
    {
        "id": "JPEG_IMG",
        "name": "JPEG Image",
        "magic": b"\xff\xd8\xff",
        "offset": 0,
        "extensions": [".jpg", ".jpeg", ".jpe"],
        "mime": "image/jpeg",
        "category": "image"
    },
    {
        "id": "GIF87_IMG",
        "name": "GIF Image (87a)",
        "magic": b"GIF87a",
        "offset": 0,
        "extensions": [".gif"],
        "mime": "image/gif",
        "category": "image"
    },
    {
        "id": "GIF89_IMG",
        "name": "GIF Image (89a)",
        "magic": b"GIF89a",
        "offset": 0,
        "extensions": [".gif"],
        "mime": "image/gif",
        "category": "image"
    },
    {
        "id": "ZIP_ARCHIVE",
        "name": "ZIP Archive / OpenXML Document",
        "magic": b"PK\x03\x04",
        "offset": 0,
        "extensions": [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"],
        "mime": "application/zip",
        "category": "archive_or_office"
    },
    {
        "id": "ZIP_EMPTY",
        "name": "Empty ZIP Archive",
        "magic": b"PK\x05\x06",
        "offset": 0,
        "extensions": [".zip"],
        "mime": "application/zip",
        "category": "archive"
    },
    {
        "id": "7Z_ARCHIVE",
        "name": "7-Zip Compressed Archive",
        "magic": b"7z\xbc\xaf\x27\x1c",
        "offset": 0,
        "extensions": [".7z"],
        "mime": "application/x-7z-compressed",
        "category": "archive"
    },
    {
        "id": "RAR_ARCHIVE",
        "name": "RAR Archive",
        "magic": b"Rar!\x1a\x07",
        "offset": 0,
        "extensions": [".rar"],
        "mime": "application/x-rar-compressed",
        "category": "archive"
    },
    {
        "id": "GZIP_ARCHIVE",
        "name": "GZIP Archive",
        "magic": b"\x1f\x8b",
        "offset": 0,
        "extensions": [".gz", ".tgz"],
        "mime": "application/gzip",
        "category": "archive"
    },
    {
        "id": "OLE_OFFICE",
        "name": "Microsoft Compound File (Legacy Office .doc/.xls/.ppt)",
        "magic": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "offset": 0,
        "extensions": [".doc", ".xls", ".ppt", ".msi"],
        "mime": "application/x-ole-storage",
        "category": "document"
    },
    {
        "id": "SHELL_SCRIPT",
        "name": "Unix Script with Shebang",
        "magic": b"#!",
        "offset": 0,
        "extensions": [".sh", ".bash", ".py", ".pl", ".rb"],
        "mime": "text/x-shellscript",
        "category": "script"
    },
]

# Right-To-Left Override and bidirectional unicode characters used for deception
UNICODE_SPOOF_CHARS = {
    "\u202E": "Right-to-Left Override [RLO]",
    "\u202D": "Left-to-Right Override [LRO]",
    "\u202B": "Right-to-Left Embedding [RLE]",
    "\u202A": "Left-to-Right Embedding [LRE]",
    "\u200E": "Left-to-Right Mark [LRM]",
    "\u200F": "Right-to-Left Mark [RLM]",
    "\u202C": "Pop Directional Formatting [PDF]",
}
