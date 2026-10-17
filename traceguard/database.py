"""
TRACEGUARD AI - Database Operations
Handles SQLite persistence for trusted baselines, integrity checks, and scan history.
Never silently updates baselines. Stores structured findings as JSON, never storing complete file contents.
"""

import json
import sqlite3
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from traceguard.config import DEFAULT_DB_PATH


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Creates a thread-safe connection with dict-like row access."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Initializes SQLite database tables and indexes if they do not exist."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # Baselines table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT UNIQUE NOT NULL,
                file_name TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_type TEXT,
                entropy REAL,
                trusted_notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)

        # Scans history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                sha1_hash TEXT,
                md5_hash TEXT,
                file_size INTEGER NOT NULL,
                detected_mime TEXT,
                file_extension TEXT,
                entropy REAL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                integrity_status TEXT NOT NULL,
                baseline_id INTEGER,
                baseline_hash TEXT,
                findings_json TEXT,
                recommendation_json TEXT,
                scanned_at TEXT NOT NULL,
                FOREIGN KEY (baseline_id) REFERENCES baselines (id) ON DELETE SET NULL
            );
        """)

        # Indexes for fast search and aggregation
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_baselines_ident ON baselines(identifier);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_baselines_hash ON baselines(sha256_hash);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_hash ON scans(sha256_hash);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(integrity_status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_level);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scanned_at);")

        conn.commit()


# ============================================================================
# BASELINE OPERATIONS
# ============================================================================

def get_baseline_by_identifier(identifier: str, db_path: Path = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves a baseline by its unique identifier (e.g., filename or custom tag)."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM baselines WHERE identifier = ? COLLATE NOCASE",
            (identifier.strip(),)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_baseline_by_hash(sha256_hash: str, db_path: Path = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves a baseline matching a given SHA-256 hash."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM baselines WHERE sha256_hash = ? COLLATE NOCASE",
            (sha256_hash.strip().lower(),)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def list_baselines(search_query: str = "", db_path: Path = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Returns all registered baselines, optionally filtered by query."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        if search_query:
            q = f"%{search_query.strip()}%"
            cursor.execute("""
                SELECT * FROM baselines
                WHERE identifier LIKE ? OR file_name LIKE ? OR sha256_hash LIKE ? OR trusted_notes LIKE ?
                ORDER BY updated_at DESC
            """, (q, q, q, q))
        else:
            cursor.execute("SELECT * FROM baselines ORDER BY updated_at DESC")
        return [dict(row) for row in cursor.fetchall()]


def register_baseline(
    identifier: str,
    file_name: str,
    sha256_hash: str,
    file_size: int,
    file_type: str = "",
    entropy: float = 0.0,
    trusted_notes: str = "",
    db_path: Path = DEFAULT_DB_PATH
) -> int:
    """
    Registers a new file fingerprint as a trusted baseline.
    Raises ValueError if the identifier is already registered.
    """
    existing = get_baseline_by_identifier(identifier, db_path)
    if existing:
        raise ValueError(
            f"Baseline identifier '{identifier}' already exists with hash: {existing['sha256_hash'][:16]}..."
        )

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO baselines (
                identifier, file_name, sha256_hash, file_size,
                file_type, entropy, trusted_notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            identifier.strip(), file_name.strip(), sha256_hash.strip().lower(),
            file_size, file_type, entropy, trusted_notes.strip(), now, now
        ))
        conn.commit()
        return cursor.lastrowid


def update_baseline(
    baseline_id: int,
    new_sha256_hash: str,
    new_file_size: int,
    new_entropy: float = 0.0,
    notes_append: str = "",
    db_path: Path = DEFAULT_DB_PATH
) -> bool:
    """
    Explicitly updates an existing baseline. Must only be invoked after explicit user confirmation.
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT trusted_notes FROM baselines WHERE id = ?", (baseline_id,))
        row = cursor.fetchone()
        if not row:
            return False

        old_notes = row["trusted_notes"] or ""
        updated_notes = (
            f"{old_notes}\n[{now[:10]}] Updated baseline hash to {new_sha256_hash[:16]}...: {notes_append}".strip()
        )

        cursor.execute("""
            UPDATE baselines
            SET sha256_hash = ?, file_size = ?, entropy = ?, trusted_notes = ?, updated_at = ?
            WHERE id = ?
        """, (new_sha256_hash.strip().lower(), new_file_size, new_entropy, updated_notes, now, baseline_id))
        conn.commit()
        return cursor.rowcount > 0


def delete_baseline(baseline_id: int, db_path: Path = DEFAULT_DB_PATH) -> bool:
    """Removes a baseline by id."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM baselines WHERE id = ?", (baseline_id,))
        conn.commit()
        return cursor.rowcount > 0


# ============================================================================
# SCAN HISTORY OPERATIONS
# ============================================================================

def record_scan(
    file_name: str,
    sha256_hash: str,
    file_size: int,
    risk_score: int,
    risk_level: str,
    integrity_status: str,
    sha1_hash: str = "",
    md5_hash: str = "",
    detected_mime: str = "",
    file_extension: str = "",
    entropy: float = 0.0,
    baseline_id: Optional[int] = None,
    baseline_hash: Optional[str] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    recommendation: Optional[Dict[str, Any]] = None,
    db_path: Path = DEFAULT_DB_PATH
) -> int:
    """Saves a scan event into SQLite with structured JSON findings."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    findings_str = json.dumps(findings or [])
    rec_str = json.dumps(recommendation or {})

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (
                file_name, sha256_hash, sha1_hash, md5_hash, file_size,
                detected_mime, file_extension, entropy, risk_score, risk_level,
                integrity_status, baseline_id, baseline_hash, findings_json,
                recommendation_json, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            file_name, sha256_hash.lower(), sha1_hash.lower(), md5_hash.lower(),
            file_size, detected_mime, file_extension, entropy, risk_score,
            risk_level, integrity_status, baseline_id,
            baseline_hash.lower() if baseline_hash else None,
            findings_str, rec_str, now
        ))
        conn.commit()
        return cursor.lastrowid


def get_scans(
    limit: int = 100,
    offset: int = 0,
    risk_filter: Optional[str] = None,
    integrity_filter: Optional[str] = None,
    search_query: str = "",
    db_path: Path = DEFAULT_DB_PATH
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Retrieves filtered and paginated scan records.
    Returns (scans_list, total_count).
    """
    conditions = []
    params = []

    if risk_filter and risk_filter.upper() != "ALL":
        conditions.append("risk_level = ?")
        params.append(risk_filter.upper())

    if integrity_filter and integrity_filter.upper() != "ALL":
        conditions.append("integrity_status = ?")
        params.append(integrity_filter.upper())

    if search_query:
        q = f"%{search_query.strip()}%"
        conditions.append("(file_name LIKE ? OR sha256_hash LIKE ?)")
        params.extend([q, q])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # Count total matches
        cursor.execute(f"SELECT COUNT(*) as total FROM scans {where_clause}", tuple(params))
        total = cursor.fetchone()["total"]

        # Fetch records
        query = f"""
            SELECT * FROM scans
            {where_clause}
            ORDER BY scanned_at DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(query, tuple(params + [limit, offset]))
        rows = [dict(r) for r in cursor.fetchall()]

        # Parse JSON fields
        for r in rows:
            try:
                r["findings"] = json.loads(r.get("findings_json") or "[]")
            except Exception:
                r["findings"] = []
            try:
                r["recommendation"] = json.loads(r.get("recommendation_json") or "{}")
            except Exception:
                r["recommendation"] = {}

        return rows, total


def get_scan_by_id(scan_id: int, db_path: Path = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves full scan details by scan_id."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        res = dict(row)
        try:
            res["findings"] = json.loads(res.get("findings_json") or "[]")
        except Exception:
            res["findings"] = []
        try:
            res["recommendation"] = json.loads(res.get("recommendation_json") or "{}")
        except Exception:
            res["recommendation"] = {}
        return res


def get_scan_stats(db_path: Path = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """
    Computes dashboard aggregate metrics:
    - Total files scanned
    - Changed fingerprints (Integrity alerts)
    - Files requiring investigation (High/Critical or Changed)
    - Verified unchanged files
    - Risk distribution
    - Integrity distribution
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # Total scans
        cursor.execute("SELECT COUNT(*) as c FROM scans")
        total_scans = cursor.fetchone()["c"]

        # Status counts
        cursor.execute("""
            SELECT integrity_status, COUNT(*) as c
            FROM scans
            GROUP BY integrity_status
        """)
        integrity_counts = {row["integrity_status"]: row["c"] for row in cursor.fetchall()}

        unchanged_count = integrity_counts.get("UNCHANGED", 0)
        changed_count = integrity_counts.get("CHANGED", 0)
        unknown_count = integrity_counts.get("UNKNOWN", 0)

        # Risk level distribution
        cursor.execute("""
            SELECT risk_level, COUNT(*) as c
            FROM scans
            GROUP BY risk_level
        """)
        risk_counts = {row["risk_level"]: row["c"] for row in cursor.fetchall()}

        # Files requiring investigation:
        # High, Critical, or Changed
        cursor.execute("""
            SELECT COUNT(*) as c FROM scans
            WHERE risk_level IN ('HIGH', 'CRITICAL') OR integrity_status = 'CHANGED'
        """)
        investigation_required = cursor.fetchone()["c"]

        # Baselines total
        cursor.execute("SELECT COUNT(*) as c FROM baselines")
        total_baselines = cursor.fetchone()["c"]

        # Recent 5 scans
        cursor.execute("""
            SELECT id, file_name, sha256_hash, risk_score, risk_level, integrity_status, scanned_at
            FROM scans
            ORDER BY scanned_at DESC
            LIMIT 5
        """)
        recent_scans = [dict(r) for r in cursor.fetchall()]

        return {
            "total_scans": total_scans,
            "changed_count": changed_count,
            "unchanged_count": unchanged_count,
            "unknown_count": unknown_count,
            "investigation_required": investigation_required,
            "total_baselines": total_baselines,
            "risk_counts": {
                "SAFE": risk_counts.get("SAFE", 0),
                "LOW": risk_counts.get("LOW", 0),
                "MEDIUM": risk_counts.get("MEDIUM", 0),
                "HIGH": risk_counts.get("HIGH", 0),
                "CRITICAL": risk_counts.get("CRITICAL", 0),
            },
            "recent_scans": recent_scans
        }


def clear_history(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Clears all scan history while retaining trusted baselines."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans;")
        conn.commit()
