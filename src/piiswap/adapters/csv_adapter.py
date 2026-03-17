"""CSV and TSV file adapter with column-aware anonymization support."""

import csv
from pathlib import Path
from typing import Callable, List, Optional

from piiswap.adapters.base import FileAdapter, register_adapter


@register_adapter
class CsvAdapter(FileAdapter):
    """Handles CSV and TSV files.

    Falls back to plain-text read/write for scan and standard anonymization.
    Provides column-aware anonymization via anonymize_column_aware().
    """

    supported_extensions = (".csv", ".tsv")

    # ---------- plain read/write (used by scan and two-pass directory flow) ----------

    def read(self, path: Path) -> str:
        """Read file as plain text (UTF-8 with latin-1 fallback)."""
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1")

    def write(self, path: Path, content: str) -> None:
        """Write plain text content (UTF-8)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    # ---------- column-aware interface ----------

    def supports_columns(self) -> bool:
        return True

    def anonymize_column_aware(
        self,
        input_path: Path,
        output_path: Path,
        replace_fn,
        pii_columns: Optional[List[str]] = None,
        keep_columns: Optional[List[str]] = None,
    ) -> None:
        """Anonymize only specific columns in a CSV/TSV file.

        Column selection priority:
        - ``pii_columns`` given   → anonymize only those columns
        - ``keep_columns`` given  → anonymize every column EXCEPT those
        - neither given           → anonymize all columns (same as plain flow)

        Args:
            input_path:  Source CSV/TSV file.
            output_path: Destination file (created with UTF-8 encoding).
            replace_fn:  Callable that takes a cell string and returns the
                         anonymized/de-anonymized version.
            pii_columns: Column names that should be anonymized.
            keep_columns: Column names that must NOT be anonymized.
        """
        delimiter = "\t" if input_path.suffix.lower() == ".tsv" else ","

        # Read with encoding fallback
        try:
            raw = input_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raw = input_path.read_text(encoding="latin-1")

        reader = csv.DictReader(raw.splitlines(), delimiter=delimiter)

        if reader.fieldnames is None:
            # Empty file — just copy as-is
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(raw, encoding="utf-8")
            return

        headers: List[str] = list(reader.fieldnames)

        # Resolve target columns
        target_columns = _resolve_target_columns(headers, pii_columns, keep_columns)

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", newline="", encoding="utf-8") as out_fh:
            writer = csv.DictWriter(
                out_fh,
                fieldnames=headers,
                delimiter=delimiter,
                extrasaction="ignore",
            )
            writer.writeheader()

            for row in reader:
                new_row = {}
                for col in headers:
                    cell = row.get(col, "")
                    if col in target_columns and cell:
                        # If replace_fn accepts column_name (engine.anonymize_cell),
                        # pass it for blind-mode PII type inference
                        if hasattr(replace_fn, '__func__') or callable(replace_fn):
                            try:
                                new_row[col] = replace_fn(cell, column_name=col)
                            except TypeError:
                                new_row[col] = replace_fn(cell)
                        else:
                            new_row[col] = replace_fn(cell)
                    else:
                        new_row[col] = cell
                writer.writerow(new_row)


# ---------- helpers ----------

def _resolve_target_columns(
    headers: List[str],
    pii_columns: Optional[List[str]],
    keep_columns: Optional[List[str]],
) -> set:
    """Return the set of column names that should be processed.

    Matching is case-insensitive: a template with "Username" will match
    a CSV header "username" or "USERNAME".
    """
    # Build a case-insensitive lookup: lowered → actual header name
    header_lower = {h.lower(): h for h in headers}

    if pii_columns:
        return {header_lower[c.lower()] for c in pii_columns if c.lower() in header_lower}
    if keep_columns:
        keep_lower = {c.lower() for c in keep_columns}
        return {h for h in headers if h.lower() not in keep_lower}
    # No filter — anonymize all columns
    return set(headers)
