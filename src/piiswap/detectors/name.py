"""Detect first names and last names using flashtext wordlists."""

import csv
from pathlib import Path
from typing import List, Optional

from flashtext import KeywordProcessor

from piiswap.detectors.base import BaseDetector, PIIMatch

# Minimum length for standalone name matching to reduce false positives
MIN_STANDALONE_NAME_LEN = 4

# Default data directory (relative to package)
_DATA_DIR = Path(__file__).parent.parent / "data"


def _load_csv_column(path: Path, column: str) -> list[str]:
    """Load a single column from a CSV file."""
    values = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            val = row.get(column, "").strip()
            if val:
                values.append(val)
    return values


class NameDetector(BaseDetector):
    """Detects first and last names using flashtext keyword matching.

    Supports two modes:
    - strict=True: only matches full name pairs (firstname + lastname adjacent)
    - strict=False: matches individual names with minimum length filter
    """

    pii_type = "name"

    def __init__(
        self,
        firstnames: Optional[list[str]] = None,
        lastnames: Optional[list[str]] = None,
        data_dir: Optional[Path] = None,
        strict: bool = False,
        case_sensitive: bool = True,
    ):
        self.strict = strict
        self._data_dir = data_dir or _DATA_DIR

        # Load wordlists
        self._firstnames_raw = firstnames or self._load_default_firstnames()
        self._lastnames_raw = lastnames or self._load_default_lastnames()

        # Build sets for quick lookup
        self._firstname_set = {n.lower() for n in self._firstnames_raw}
        self._lastname_set = {n.lower() for n in self._lastnames_raw}

        # Build flashtext processors
        self._first_kp = KeywordProcessor(case_sensitive=case_sensitive)
        self._last_kp = KeywordProcessor(case_sensitive=case_sensitive)

        for name in self._firstnames_raw:
            if len(name) >= MIN_STANDALONE_NAME_LEN:
                self._first_kp.add_keyword(name, name)
                # Also add capitalized variant
                cap = name.capitalize()
                if cap != name:
                    self._first_kp.add_keyword(cap, name)

        for name in self._lastnames_raw:
            if len(name) >= MIN_STANDALONE_NAME_LEN:
                self._last_kp.add_keyword(name, name)
                cap = name.capitalize()
                if cap != name:
                    self._last_kp.add_keyword(cap, name)

    def _load_default_firstnames(self) -> list[str]:
        names = []
        for fname in ("be_firstnames.csv", "firstnames.csv"):
            path = self._data_dir / fname
            if path.exists():
                # Try common column names
                for col in ("voornaam", "firstname", "name"):
                    try:
                        names.extend(_load_csv_column(path, col))
                        break
                    except (KeyError, StopIteration):
                        continue
        return list(set(names))

    def _load_default_lastnames(self) -> list[str]:
        names = []
        for fname in ("be_lastnames.csv", "lastnames.csv"):
            path = self._data_dir / fname
            if path.exists():
                for col in ("achternaam", "lastname", "name"):
                    try:
                        names.extend(_load_csv_column(path, col))
                        break
                    except (KeyError, StopIteration):
                        continue
        return list(set(names))

    def detect(self, text: str) -> List[PIIMatch]:
        if self.strict:
            return self._detect_strict(text)
        return self._detect_loose(text)

    def _detect_loose(self, text: str) -> List[PIIMatch]:
        """Match individual names with minimum length filter."""
        matches = []

        # Use flashtext for efficient matching
        for kp, pii_sub_type in [
            (self._first_kp, "firstname"),
            (self._last_kp, "lastname"),
        ]:
            keywords = kp.extract_keywords(text, span_info=True)
            for keyword, start, end in keywords:
                matches.append(PIIMatch(
                    start=start,
                    end=end,
                    raw_value=text[start:end],
                    pii_type=pii_sub_type,
                    confidence=0.70,
                ))
        return matches

    def _detect_strict(self, text: str) -> List[PIIMatch]:
        """Only match when a firstname and lastname appear adjacent (full name)."""
        matches = []
        words = list(self._iter_words(text))

        for i in range(len(words) - 1):
            word1, start1, end1 = words[i]
            word2, start2, end2 = words[i + 1]

            is_first_last = (
                word1.lower() in self._firstname_set
                and word2.lower() in self._lastname_set
            )
            is_last_first = (
                word1.lower() in self._lastname_set
                and word2.lower() in self._firstname_set
            )

            if is_first_last:
                matches.append(PIIMatch(
                    start=start1, end=end1,
                    raw_value=word1, pii_type="firstname", confidence=0.90,
                ))
                matches.append(PIIMatch(
                    start=start2, end=end2,
                    raw_value=word2, pii_type="lastname", confidence=0.90,
                ))
            elif is_last_first:
                matches.append(PIIMatch(
                    start=start1, end=end1,
                    raw_value=word1, pii_type="lastname", confidence=0.90,
                ))
                matches.append(PIIMatch(
                    start=start2, end=end2,
                    raw_value=word2, pii_type="firstname", confidence=0.90,
                ))

        return matches

    @staticmethod
    def _iter_words(text: str):
        """Yield (word, start, end) tuples from text."""
        import re
        for m in re.finditer(r'\b[A-Za-zÀ-ÿ]{2,}\b', text):
            yield m.group(), m.start(), m.end()
