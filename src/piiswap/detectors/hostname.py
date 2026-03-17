"""Detect PII embedded in hostnames (e.g., LAPTOP-JOHN, DESKTOP-ADMIN-DOE)."""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# Common hostname prefixes that often contain user names
HOSTNAME_PII_RE = re.compile(
    r'\b((?:LAPTOP|DESKTOP|PC|WORKSTATION|NB|NOTEBOOK)[-_]'
    r'[A-Za-z][A-Za-z0-9_-]{2,})\b',
    re.IGNORECASE,
)

# Pure machine identifiers (no PII)
MACHINE_ID_RE = re.compile(r'^[A-Z]+-[A-Z0-9]{6,}$', re.IGNORECASE)


class HostnamePIIDetector(BaseDetector):
    pii_type = "hostname"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        for m in HOSTNAME_PII_RE.finditer(text):
            hostname = m.group(1)

            # Skip if it looks like a random machine ID (e.g., DESKTOP-ABC123DE)
            if MACHINE_ID_RE.match(hostname):
                # Check if the suffix part has any lowercase or is clearly a name
                suffix = hostname.split("-", 1)[1] if "-" in hostname else ""
                if suffix.isalnum() and suffix.isupper() and len(suffix) >= 7:
                    continue  # Likely a random Windows hostname

            matches.append(PIIMatch(
                start=m.start(),
                end=m.end(),
                raw_value=hostname,
                pii_type=self.pii_type,
                confidence=0.70,
            ))
        return matches
