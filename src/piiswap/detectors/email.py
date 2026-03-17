"""Detect email addresses."""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# Simplified RFC 5322 - catches real-world emails without matching hashes or IPs
EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
)


class EmailDetector(BaseDetector):
    pii_type = "email"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        for m in EMAIL_RE.finditer(text):
            matches.append(PIIMatch(
                start=m.start(),
                end=m.end(),
                raw_value=m.group(),
                pii_type=self.pii_type,
                confidence=0.95,
            ))
        return matches
