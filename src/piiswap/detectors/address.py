"""Detect street addresses using flashtext wordlists."""

import csv
from pathlib import Path
from typing import List, Optional

from flashtext import KeywordProcessor

from piiswap.detectors.base import BaseDetector, PIIMatch

_DATA_DIR = Path(__file__).parent.parent / "data"


class AddressDetector(BaseDetector):
    """Detects street names from Belgian and custom wordlists."""

    pii_type = "address"

    def __init__(
        self,
        streets: Optional[list[str]] = None,
        data_dir: Optional[Path] = None,
        case_sensitive: bool = True,
    ):
        self._data_dir = data_dir or _DATA_DIR
        self._streets = streets or self._load_default_streets()

        self._kp = KeywordProcessor(case_sensitive=case_sensitive)
        for street in self._streets:
            if len(street) >= 5:  # Skip very short street names
                self._kp.add_keyword(street, street)
                cap = street.capitalize()
                if cap != street:
                    self._kp.add_keyword(cap, street)

    def _load_default_streets(self) -> list[str]:
        streets = []
        path = self._data_dir / "be_streets.csv"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    val = row.get("street", "").strip()
                    if val:
                        streets.append(val)
        return streets

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        keywords = self._kp.extract_keywords(text, span_info=True)
        for keyword, start, end in keywords:
            matches.append(PIIMatch(
                start=start,
                end=end,
                raw_value=text[start:end],
                pii_type=self.pii_type,
                confidence=0.80,
            ))
        return matches
