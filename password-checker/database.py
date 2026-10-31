"""
database.py – SQLite schema setup and connection helpers
SecureGuard Password Strength Analyzer
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "secureguard.db")


def get_connection():
    """Return a thread-safe SQLite connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they do not exist. Called once on server startup."""
    conn = get_connection()
    cursor = conn.cursor()

    # ── ACCOUNTS TABLE ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id         INTEGER  PRIMARY KEY AUTOINCREMENT,
            username   TEXT     NOT NULL UNIQUE COLLATE NOCASE,
            created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)

    # ── PASSWORD HISTORY TABLE ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id          INTEGER  PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER  NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            password    TEXT     NOT NULL,
            score       REAL     NOT NULL,
            grade       TEXT     NOT NULL,
            length      INTEGER  NOT NULL,
            has_upper   INTEGER  NOT NULL DEFAULT 0,
            has_lower   INTEGER  NOT NULL DEFAULT 0,
            has_number  INTEGER  NOT NULL DEFAULT 0,
            has_special INTEGER  NOT NULL DEFAULT 0,
            no_repeat   INTEGER  NOT NULL DEFAULT 0,
            is_common   INTEGER  NOT NULL DEFAULT 0,
            entropy     REAL     NOT NULL DEFAULT 0.0,
            created_at  DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Database ready at: {DB_PATH}")


# ──────────────────────────────────────────
# Account helpers
# ──────────────────────────────────────────

def get_or_create_account(username: str) -> dict:
    """Return existing account or create a new one."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM accounts WHERE username = ? COLLATE NOCASE", (username,))
        row = cur.fetchone()
        if row:
            return dict(row)
        cur.execute("INSERT INTO accounts (username) VALUES (?)", (username,))
        conn.commit()
        cur.execute("SELECT * FROM accounts WHERE id = ?", (cur.lastrowid,))
        return dict(cur.fetchone())
    finally:
        conn.close()


def account_by_username(username: str) -> dict | None:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM accounts WHERE username = ? COLLATE NOCASE", (username,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ──────────────────────────────────────────
# History helpers
# ──────────────────────────────────────────

def save_password(account_id: int, analysis: dict) -> dict:
    """Insert a password analysis result and return the new record."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO password_history
                (account_id, password, score, grade, length,
                 has_upper, has_lower, has_number, has_special,
                 no_repeat, is_common, entropy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            account_id,
            analysis["password"],
            analysis["score"],
            analysis["grade"],
            analysis["length"],
            int(analysis["has_upper"]),
            int(analysis["has_lower"]),
            int(analysis["has_number"]),
            int(analysis["has_special"]),
            int(analysis["no_repeat"]),
            int(analysis["is_common"]),
            analysis["entropy"],
        ))
        conn.commit()
        cur.execute("SELECT * FROM password_history WHERE id = ?", (cur.lastrowid,))
        return dict(cur.fetchone())
    finally:
        conn.close()


def get_history(account_id: int) -> list[dict]:
    """Return all password history for an account, newest first."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM password_history
            WHERE account_id = ?
            ORDER BY created_at DESC
        """, (account_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def delete_entry(entry_id: int, account_id: int) -> bool:
    """Delete a history entry. Returns True if a row was deleted."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM password_history WHERE id = ? AND account_id = ?",
            (entry_id, account_id)
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_stats(account_id: int) -> dict:
    """Compute aggregate stats for an account."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT
                COUNT(*)                           AS total,
                ROUND(AVG(score), 1)               AS avg_score,
                ROUND(MAX(score), 1)               AS best_score,
                SUM(CASE WHEN score < 4 THEN 1 ELSE 0 END) AS weak_count
            FROM password_history
            WHERE account_id = ?
        """, (account_id,))
        row = cur.fetchone()
        return dict(row) if row else {"total": 0, "avg_score": None, "best_score": None, "weak_count": 0}
    finally:
        conn.close()
