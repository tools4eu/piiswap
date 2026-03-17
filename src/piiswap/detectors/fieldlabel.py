"""Context-driven PII detector: uses field labels/keys to identify values.

Instead of recognizing PII by its content (e.g., "is this a name?"), this
detector uses the surrounding label/key to KNOW the value is PII.

If a field says "display_name", "subscriber_name", or "full_name",
the value MUST be a name — regardless of whether it's in a wordlist.

Covers:
- JSON: "display_name": "Tom V."
- Key=value: subscriber_name = Tom Vandenberghe
- CSV/log: after known field labels
- INI/config: name = value
"""

import re
from typing import List, Tuple

from piiswap.detectors.base import BaseDetector, PIIMatch

# ---------------------------------------------------------------------------
# Field label → PII type mapping
# Each tuple: (compiled regex, pii_type, confidence)
# The regex MUST have group(1) capturing the VALUE.
# ---------------------------------------------------------------------------

# Value pattern: captures quoted or unquoted values
# Quoted: "value" or 'value' — captures content between quotes
# Unquoted: captures until end of line, comma, or closing brace
_QUOTED_VAL = r'"([^"]{1,100})"'
_QUOTED_VAL_SINGLE = r"'([^']{1,100})'"
_UNQUOTED_VAL = r'([^\s,;}\]"\']{1,100})'

def _make_patterns(labels: str, pii_type: str, confidence: float) -> List[Tuple[re.Pattern, str, float]]:
    """Generate JSON + key=value + key: value patterns for a set of labels."""
    results = []
    # JSON style: "label": "value" or "label": 'value'
    results.append((
        re.compile(
            rf'["\']?(?:{labels})["\']?\s*:\s*{_QUOTED_VAL}',
            re.IGNORECASE,
        ),
        pii_type,
        confidence,
    ))
    results.append((
        re.compile(
            rf'["\']?(?:{labels})["\']?\s*:\s*{_QUOTED_VAL_SINGLE}',
            re.IGNORECASE,
        ),
        pii_type,
        confidence,
    ))
    # Key=value style: label = value or label=value
    results.append((
        re.compile(
            rf'(?:{labels})\s*=\s*{_QUOTED_VAL}',
            re.IGNORECASE,
        ),
        pii_type,
        confidence,
    ))
    results.append((
        re.compile(
            rf'(?:{labels})\s*=\s*{_UNQUOTED_VAL}',
            re.IGNORECASE,
        ),
        pii_type,
        confidence,
    ))
    return results


# --- Name fields (display_name, full_name, subscriber_name, etc.) ---
_NAME_LABELS = (
    r'display[_\s]?name|full[_\s]?name|real[_\s]?name'
    r'|subscriber[_\s]?name|account[_\s]?name|holder[_\s]?name'
    r'|contact[_\s]?name|customer[_\s]?name|owner[_\s]?name'
    r'|first[_\s]?name|last[_\s]?name|family[_\s]?name|given[_\s]?name'
    r'|naam|achternaam|voornaam'  # Dutch
)

# --- Username fields ---
_USERNAME_LABELS = (
    r'user[_\s]?name|login[_\s]?name|screen[_\s]?name|nick[_\s]?name'
    r'|user[_\s]?id|account[_\s]?id|member[_\s]?name|caller[_\s]?id'
    r'|sender[_\s]?name|author[_\s]?name|creator[_\s]?name'
    r'|gebruikersnaam'  # Dutch
)

# --- Address fields ---
_ADDRESS_LABELS = (
    r'address|street[_\s]?address|home[_\s]?address|postal[_\s]?address'
    r'|mailing[_\s]?address|residence|domicile'
    r'|adres|woonadres|verblijfplaats'  # Dutch
)

# --- Phone fields ---
_PHONE_LABELS = (
    r'phone[_\s]?number|telephone|mobile[_\s]?number|cell[_\s]?phone'
    r'|contact[_\s]?number|gsm[_\s]?number|tel[_\s]?number'
    r'|telefoon|gsm|mobiel'  # Dutch
)

# --- Build all patterns ---
FIELD_PATTERNS: List[Tuple[re.Pattern, str, float]] = []
FIELD_PATTERNS.extend(_make_patterns(_NAME_LABELS, "name", 0.92))
FIELD_PATTERNS.extend(_make_patterns(_USERNAME_LABELS, "username", 0.90))
FIELD_PATTERNS.extend(_make_patterns(_ADDRESS_LABELS, "address", 0.88))
FIELD_PATTERNS.extend(_make_patterns(_PHONE_LABELS, "phone", 0.88))

# Values to skip (too generic, not actual PII)
_FALSE_POSITIVES = {
    '', 'null', 'none', 'n/a', 'unknown', 'undefined', 'not set',
    'true', 'false', 'yes', 'no',
    'admin', 'root', 'system', 'administrator', 'default', 'guest',
    'test', 'example', 'demo', 'sample',
    'verified', 'unverified', 'active', 'inactive', 'pending',
}


class FieldLabelDetector(BaseDetector):
    """Detect PII values based on their field label/key context.

    When a field says "display_name", the value is always a name —
    no wordlist matching needed.
    """

    pii_type = "name"  # Default; individual matches override this

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        seen_spans = set()

        for pattern, pii_type, confidence in FIELD_PATTERNS:
            for m in pattern.finditer(text):
                value = m.group(1).strip()

                # Skip false positives
                if value.lower() in _FALSE_POSITIVES:
                    continue

                # Skip very short values (likely abbreviations or initials)
                if len(value) < 3:
                    continue

                # Skip pure numeric (likely an ID, not PII name)
                if value.isdigit():
                    continue

                start = m.start(1)
                end = m.end(1)

                # Avoid duplicate matches on same span
                span_key = (start, end)
                if span_key in seen_spans:
                    continue
                seen_spans.add(span_key)

                matches.append(PIIMatch(
                    start=start,
                    end=end,
                    raw_value=value,
                    pii_type=pii_type,
                    confidence=confidence,
                ))

        return matches
