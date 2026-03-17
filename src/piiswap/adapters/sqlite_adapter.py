"""SQLite database adapter — anonymizes text content in all text columns."""

import sqlite3
from pathlib import Path

from piiswap.adapters.base import FileAdapter, register_adapter


@register_adapter
class SqliteAdapter(FileAdapter):
    """Read and anonymize SQLite databases.

    Reads all text columns from all tables and concatenates for PII detection.
    Write creates an anonymized copy of the database with text columns replaced.
    """

    supported_extensions = (".db", ".sqlite", ".sqlite3")

    def read(self, path: Path) -> str:
        """Read all text content from all tables."""
        parts = []
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row

        try:
            tables = self._get_tables(conn)
            for table_name in tables:
                columns = self._get_text_columns(conn, table_name)
                if not columns:
                    continue

                parts.append(f"--- Table: {table_name} ---")
                col_list = ", ".join(columns)
                cursor = conn.execute(f'SELECT rowid, {col_list} FROM "{table_name}"')

                for row in cursor:
                    for col in columns:
                        val = row[col]
                        if val and isinstance(val, str) and val.strip():
                            parts.append(f"[{table_name}.{col}] {val}")
        finally:
            conn.close()

        return "\n".join(parts)

    def write(self, path: Path, content: str) -> None:
        """Write anonymized text back. For SQLite this is a text dump."""
        path.parent.mkdir(parents=True, exist_ok=True)
        txt_path = path.with_suffix(".txt")
        txt_path.write_text(content, encoding="utf-8")

    def anonymize_database(self, input_path: Path, output_path: Path, replace_fn) -> None:
        """Create an anonymized copy of the SQLite database.

        replace_fn: callable that takes a string and returns anonymized string.
        Copies the database and replaces text content in-place in the copy.
        """
        import shutil

        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(input_path), str(output_path))

        conn = sqlite3.connect(str(output_path))
        try:
            tables = self._get_tables(conn)
            for table_name in tables:
                columns = self._get_text_columns(conn, table_name)
                if not columns:
                    continue

                col_list = ", ".join(columns)
                cursor = conn.execute(f'SELECT rowid, {col_list} FROM "{table_name}"')

                for row in cursor.fetchall():
                    rowid = row[0]
                    updates = {}
                    for i, col in enumerate(columns):
                        val = row[i + 1]
                        if val and isinstance(val, str) and val.strip():
                            new_val = replace_fn(val)
                            if new_val != val:
                                updates[col] = new_val

                    if updates:
                        set_clause = ", ".join(f'"{col}" = ?' for col in updates)
                        values = list(updates.values()) + [rowid]
                        conn.execute(
                            f'UPDATE "{table_name}" SET {set_clause} WHERE rowid = ?',
                            values,
                        )

            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _get_tables(conn: sqlite3.Connection) -> list:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        return [row[0] for row in cursor]

    @staticmethod
    def _get_text_columns(conn: sqlite3.Connection, table_name: str) -> list:
        cursor = conn.execute(f'PRAGMA table_info("{table_name}")')
        return [
            row[1] for row in cursor
            if row[2].upper() in ("TEXT", "VARCHAR", "CHAR", "CLOB", "")
        ]
