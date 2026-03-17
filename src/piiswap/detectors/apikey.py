"""Detect API keys and tokens based on known prefixes and entropy."""

import math
import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# Known API key patterns (prefix + length)
KNOWN_KEY_PATTERNS = [
    # AWS
    re.compile(r'\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'),
    # AWS Secret Key (base64-ish, 40 chars)
    re.compile(r'(?<=[\s="\':])(?:[A-Za-z0-9+/]{40})(?=[\s"\';\n])'),
    # Google API
    re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'),
    # Stripe
    re.compile(r'\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b'),
    # Generic Bearer tokens (long hex/base64)
    re.compile(r'\b[a-f0-9]{32,64}\b(?!\s*[.:])')  ,
    # GitHub tokens
    re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b'),
    # Telegram Bot tokens
    re.compile(r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b'),
    # Generic long alphanumeric tokens (32+ chars, mixed case or with special chars)
    re.compile(r'(?<=[\s="\':])(?:[A-Za-z0-9]{32,})(?=[\s"\';\n])'),
]

# Context keywords that suggest a value is an API key
KEY_CONTEXT_RE = re.compile(
    r'(?:api[_-]?key|token|secret|password|bearer|authorization|auth[_-]?token|'
    r'access[_-]?key|private[_-]?key|client[_-]?secret|app[_-]?secret)',
    re.IGNORECASE,
)

# Things that look like keys but aren't (hashes in forensic context)
HASH_CONTEXT_RE = re.compile(
    r'(?:md5|sha1|sha256|sha512|hash|checksum|digest|signature|fingerprint|cert)',
    re.IGNORECASE,
)


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class APIKeyDetector(BaseDetector):
    pii_type = "apikey"

    def __init__(self, min_entropy: float = 3.5):
        self.min_entropy = min_entropy

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        seen_spans = set()

        for pattern in KNOWN_KEY_PATTERNS:
            for m in pattern.finditer(text):
                span = (m.start(), m.end())
                if span in seen_spans:
                    continue

                value = m.group()

                # Skip short matches unless they have a known prefix
                if len(value) < 20:
                    continue

                # Skip if in hash context (forensic data often has hashes)
                context_start = max(0, m.start() - 50)
                context = text[context_start:m.start()]
                if HASH_CONTEXT_RE.search(context):
                    continue

                # Check entropy — low entropy strings are unlikely to be keys
                ent = _entropy(value)
                if ent < self.min_entropy:
                    continue

                # Higher confidence if there is key context nearby
                confidence = 0.7
                if KEY_CONTEXT_RE.search(context):
                    confidence = 0.95

                seen_spans.add(span)
                matches.append(PIIMatch(
                    start=m.start(),
                    end=m.end(),
                    raw_value=value,
                    pii_type=self.pii_type,
                    confidence=confidence,
                ))
        return matches
