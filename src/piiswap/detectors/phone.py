"""Detect phone numbers in various international formats."""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

PHONE_PATTERNS = [
    # International: +32 123 45 67 89, +1-555-123-4567
    re.compile(r'\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{0,4}\b'),
    # Belgian formats: 0471 12 34 56, 04/123.45.67, 02 123 45 67
    re.compile(r'\b0\d{1,3}[\s/.-]\d{2,3}[\s.-]\d{2}[\s.-]\d{2}\b'),
    # Generic: (555) 123-4567
    re.compile(r'\(\d{3}\)\s?\d{3}[-.]?\d{4}\b'),
    # 10+ digit sequences that look like phone numbers (with separators)
    re.compile(r'\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b'),
]

# Patterns that look like phone numbers but aren't
FALSE_POSITIVE_CONTEXT = re.compile(
    r'(?:hash|sha\d*|md5|version|v\d|port|pid|uid|gid|size|bytes|offset|0x)',
    re.IGNORECASE,
)


class PhoneDetector(BaseDetector):
    pii_type = "phone"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        seen_spans = set()

        for pattern in PHONE_PATTERNS:
            for m in pattern.finditer(text):
                # Skip if overlapping with already found match
                span = (m.start(), m.end())
                if any(s <= m.start() < e or s < m.end() <= e for s, e in seen_spans):
                    continue

                value = m.group()
                # Must have at least 7 digits
                digits = re.sub(r'\D', '', value)
                if len(digits) < 7 or len(digits) > 15:
                    continue

                # Check context for false positives
                context_start = max(0, m.start() - 30)
                context = text[context_start:m.start()]
                if FALSE_POSITIVE_CONTEXT.search(context):
                    continue

                seen_spans.add(span)
                matches.append(PIIMatch(
                    start=m.start(),
                    end=m.end(),
                    raw_value=value,
                    pii_type=self.pii_type,
                    confidence=0.85,
                ))
        return matches
