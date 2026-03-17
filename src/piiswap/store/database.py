"""Encrypted SQLite mapping store for PII ↔ token mappings."""

import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from piiswap.store.encryption import decrypt_file, encrypt_file, is_encrypted


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS entities (
    entity_id   TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS mappings (
    mapping_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id   TEXT NOT NULL REFERENCES entities(entity_id),
    pii_type    TEXT NOT NULL,
    raw_value   TEXT NOT NULL,
    token       TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    source_file TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE(raw_value, case_id)
);

CREATE TABLE IF NOT EXISTS allowlist (
    value       TEXT NOT NULL,
    value_type  TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    reason      TEXT,
    PRIMARY KEY(value, case_id)
);

CREATE TABLE IF NOT EXISTS processed_files (
    file_path       TEXT NOT NULL,
    case_id         TEXT NOT NULL,
    direction       TEXT NOT NULL,
    processed_at    TEXT NOT NULL,
    file_hash       TEXT,
    PRIMARY KEY(file_path, case_id, direction)
);

CREATE TABLE IF NOT EXISTS counters (
    pii_type    TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    next_num    INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(pii_type, case_id)
);

CREATE INDEX IF NOT EXISTS idx_mappings_raw ON mappings(raw_value);
CREATE INDEX IF NOT EXISTS idx_mappings_token ON mappings(token);
CREATE INDEX IF NOT EXISTS idx_mappings_entity ON mappings(entity_id);
CREATE INDEX IF NOT EXISTS idx_mappings_case ON mappings(case_id);
"""


class MappingStore:
    """Encrypted SQLite store for PII-to-token mappings."""

    def __init__(self, db_path: Path, password: Optional[str] = None):
        self.db_path = db_path
        self.password = password
        self._conn: Optional[sqlite3.Connection] = None
        self._tmp_path: Optional[Path] = None

    def open(self) -> None:
        if self.password and is_encrypted(self.db_path):
            self._tmp_path = Path(tempfile.mktemp(suffix=".db"))
            decrypt_file(self.db_path, self._tmp_path, self.password)
            self._conn = sqlite3.connect(str(self._tmp_path))
        elif self.db_path.exists():
            self._conn = sqlite3.connect(str(self.db_path))
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path))

        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        if self._conn is None:
            return
        self._conn.commit()
        self._conn.close()
        self._conn = None

        if self.password and self._tmp_path:
            encrypt_file(self._tmp_path, self.db_path, self.password)
            self._tmp_path.unlink(missing_ok=True)
            self._tmp_path = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not open. Call open() first.")
        return self._conn

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # --- Entity operations ---

    def create_entity(self, entity_id: str, entity_type: str, notes: str = "") -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO entities (entity_id, entity_type, created_at, notes) VALUES (?, ?, ?, ?)",
            (entity_id, entity_type, self._now(), notes),
        )
        self.conn.commit()

    def get_entity(self, entity_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM entities WHERE entity_id = ?", (entity_id,)).fetchone()
        return dict(row) if row else None

    def count_entities(self, case_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(DISTINCT entity_id) as cnt FROM mappings WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        return row["cnt"] if row else 0

    # --- Mapping operations ---

    def add_mapping(
        self,
        entity_id: str,
        pii_type: str,
        raw_value: str,
        token: str,
        case_id: str,
        source_file: str = "",
    ) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO mappings
               (entity_id, pii_type, raw_value, token, case_id, source_file, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (entity_id, pii_type, raw_value, token, case_id, source_file, self._now()),
        )
        self.conn.commit()

    def get_mapping_by_raw(self, raw_value: str, case_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM mappings WHERE raw_value = ? AND case_id = ?",
            (raw_value, case_id),
        ).fetchone()
        return dict(row) if row else None

    def get_mapping_by_token(self, token: str, case_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM mappings WHERE token = ? AND case_id = ?",
            (token, case_id),
        ).fetchone()
        return dict(row) if row else None

    def get_mappings_by_entity(self, entity_id: str, case_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM mappings WHERE entity_id = ? AND case_id = ?",
            (entity_id, case_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_mappings(self, case_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM mappings WHERE case_id = ? ORDER BY entity_id, pii_type",
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_mappings_by_types(self, case_id: str, pii_types: list) -> list[dict]:
        """Return mappings for a case filtered to the given PII types.

        Args:
            case_id: The case identifier.
            pii_types: List of pii_type values to include (e.g. ['email', 'phone']).

        Returns:
            List of mapping dicts whose pii_type is in pii_types.
        """
        if not pii_types:
            return []
        placeholders = ",".join("?" * len(pii_types))
        rows = self.conn.execute(
            f"SELECT * FROM mappings WHERE case_id = ? AND pii_type IN ({placeholders})"
            " ORDER BY entity_id, pii_type",
            (case_id, *pii_types),
        ).fetchall()
        return [dict(r) for r in rows]

    def find_entity_by_raw(self, raw_value: str, case_id: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT entity_id FROM mappings WHERE raw_value = ? AND case_id = ?",
            (raw_value, case_id),
        ).fetchone()
        return row["entity_id"] if row else None

    # --- Token counter ---

    def next_token_number(self, pii_type: str, case_id: str) -> int:
        row = self.conn.execute(
            "SELECT next_num FROM counters WHERE pii_type = ? AND case_id = ?",
            (pii_type, case_id),
        ).fetchone()
        if row:
            num = row["next_num"]
            self.conn.execute(
                "UPDATE counters SET next_num = ? WHERE pii_type = ? AND case_id = ?",
                (num + 1, pii_type, case_id),
            )
        else:
            num = 1
            self.conn.execute(
                "INSERT INTO counters (pii_type, case_id, next_num) VALUES (?, ?, ?)",
                (pii_type, case_id, 2),
            )
        self.conn.commit()
        return num

    # --- Allowlist ---

    def add_allowlist(self, value: str, value_type: str, case_id: str, reason: str = "") -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO allowlist (value, value_type, case_id, reason) VALUES (?, ?, ?, ?)",
            (value, value_type, case_id, reason),
        )
        self.conn.commit()

    def remove_allowlist(self, value: str, case_id: str) -> None:
        self.conn.execute("DELETE FROM allowlist WHERE value = ? AND case_id = ?", (value, case_id))
        self.conn.commit()

    def get_allowlist(self, case_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM allowlist WHERE case_id = ?", (case_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def is_allowlisted(self, value: str, case_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM allowlist WHERE value = ? AND case_id = ?",
            (value, case_id),
        ).fetchone()
        return row is not None

    # --- Processed files tracking ---

    def mark_processed(self, file_path: str, case_id: str, direction: str, file_hash: str = "") -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO processed_files
               (file_path, case_id, direction, processed_at, file_hash)
               VALUES (?, ?, ?, ?, ?)""",
            (file_path, case_id, direction, self._now(), file_hash),
        )
        self.conn.commit()

    def is_processed(self, file_path: str, case_id: str, direction: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM processed_files WHERE file_path = ? AND case_id = ? AND direction = ?",
            (file_path, case_id, direction),
        ).fetchone()
        return row is not None

    # --- Stats ---

    def stats(self, case_id: str) -> dict:
        mapping_count = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM mappings WHERE case_id = ?", (case_id,)
        ).fetchone()["cnt"]
        entity_count = self.count_entities(case_id)
        file_count = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM processed_files WHERE case_id = ?", (case_id,)
        ).fetchone()["cnt"]
        allowlist_count = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM allowlist WHERE case_id = ?", (case_id,)
        ).fetchone()["cnt"]

        type_counts = {}
        rows = self.conn.execute(
            "SELECT pii_type, COUNT(*) as cnt FROM mappings WHERE case_id = ? GROUP BY pii_type",
            (case_id,),
        ).fetchall()
        for r in rows:
            type_counts[r["pii_type"]] = r["cnt"]

        return {
            "case_id": case_id,
            "total_mappings": mapping_count,
            "total_entities": entity_count,
            "processed_files": file_count,
            "allowlist_entries": allowlist_count,
            "by_type": type_counts,
        }
