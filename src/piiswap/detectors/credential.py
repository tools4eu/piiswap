"""Detect credentials (password assignments) in config files and logs."""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# Patterns that capture the VALUE of password/credential assignments
CREDENTIAL_PATTERNS = [
    # key=value or key = value (config files, env vars)
    re.compile(
        r'(?:password|passwd|pwd|pass|secret|credential|auth_token|api_key|'
        r'private_key|access_key|client_secret|db_pass|db_password|mysql_pwd|'
        r'admin_pass|admin_password|smtp_password)'
        r'\s*[=:]\s*["\']?([^\s"\';\n#]+)',
        re.IGNORECASE,
    ),
    # PHP: $password = "value";
    re.compile(
        r'\$(?:password|passwd|pwd|secret|api_key|token)\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    ),
    # JSON: "password": "value"
    re.compile(
        r'"(?:password|passwd|pwd|secret|api_key|token|private_key)"\s*:\s*"([^"]+)"',
        re.IGNORECASE,
    ),
    # YAML: password: value
    re.compile(
        r'(?:password|passwd|pwd|secret|api_key|token):\s+([^\s#\n]+)',
        re.IGNORECASE,
    ),
]


class CredentialDetector(BaseDetector):
    pii_type = "password"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        seen_spans = set()

        for pattern in CREDENTIAL_PATTERNS:
            for m in pattern.finditer(text):
                # We want the captured group (the value), not the key
                if m.lastindex and m.lastindex >= 1:
                    value = m.group(1)
                    start = m.start(1)
                    end = m.end(1)
                else:
                    continue

                # Skip empty or trivial values
                if not value or len(value) < 3 or value in ('null', 'none', 'false', 'true', '***'):
                    continue

                span = (start, end)
                if span in seen_spans:
                    continue

                seen_spans.add(span)
                matches.append(PIIMatch(
                    start=start,
                    end=end,
                    raw_value=value,
                    pii_type=self.pii_type,
                    confidence=0.90,
                ))
        return matches
