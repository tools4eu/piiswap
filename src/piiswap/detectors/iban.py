"""Detect IBAN numbers with validation."""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# IBAN: 2 letter country code + 2 check digits + up to 30 alphanumeric
IBAN_RE = re.compile(r'\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4}\b')


def _validate_iban(iban: str) -> bool:
    """Basic IBAN checksum validation (ISO 13616)."""
    clean = iban.replace(" ", "").upper()
    if len(clean) < 15 or len(clean) > 34:
        return False
    # Move first 4 chars to end
    rearranged = clean[4:] + clean[:4]
    # Convert letters to numbers (A=10, B=11, ...)
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord('A') + 10)
        else:
            return False
    return int(numeric) % 97 == 1


class IBANDetector(BaseDetector):
    pii_type = "iban"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        for m in IBAN_RE.finditer(text):
            value = m.group()
            if _validate_iban(value):
                matches.append(PIIMatch(
                    start=m.start(),
                    end=m.end(),
                    raw_value=value,
                    pii_type=self.pii_type,
                    confidence=0.98,
                ))
        return matches
