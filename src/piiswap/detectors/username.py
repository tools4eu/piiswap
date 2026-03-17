"""Detect usernames in log files and configuration contexts."""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# Contexts where a username typically appears
USERNAME_CONTEXT_PATTERNS = [
    # Log file patterns: "for <username> from", "user <username>"
    re.compile(r'(?:for|user|User|USER|login|Login|account|Account)\s+([a-zA-Z][a-zA-Z0-9._-]{2,30})\b'),
    # Assignment patterns: "username = <value>", "user: <value>"
    re.compile(r'(?:username|user|operator|admin|owner)\s*[=:]\s*["\']?([a-zA-Z][a-zA-Z0-9._-]{2,30})\b', re.IGNORECASE),
    # HTTP auth log: "- <username> [" (nginx combined log format)
    re.compile(r' - ([a-zA-Z][a-zA-Z0-9._-]{2,30}) \['),
    # JSON field patterns (provider data): "username": "value", "subscriber_id": "value"
    re.compile(
        r'(?:username|user_?name|subscriber|account_?name|login_?name|member_?name|caller_?id)'
        r'"\s*:\s*"([a-zA-Z][a-zA-Z0-9._-]{2,30})"',
        re.IGNORECASE,
    ),
]

# Values that are not usernames
FALSE_POSITIVES = {
    'root', 'admin', 'administrator', 'system', 'nobody', 'daemon',
    'www-data', 'nginx', 'apache', 'mysql', 'postgres', 'redis',
    'guest', 'anonymous', 'unknown', 'null', 'none', 'default',
    'localhost', 'config', 'updated', 'deleted', 'created', 'failed',
    'invalid', 'public', 'private', 'internal', 'external',
    'true', 'false', 'yes', 'error', 'warning', 'info', 'debug',
    'admin_backup',  # generic service accounts
}


class UsernameDetector(BaseDetector):
    pii_type = "username"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        seen_values = set()

        for pattern in USERNAME_CONTEXT_PATTERNS:
            for m in pattern.finditer(text):
                if m.lastindex and m.lastindex >= 1:
                    value = m.group(1)
                    start = m.start(1)
                    end = m.end(1)
                else:
                    continue

                # Filter false positives
                if value.lower() in FALSE_POSITIVES:
                    continue

                # Must contain a dot, dash or underscore to look like a username
                # (otherwise it's likely just a word)
                if not any(c in value for c in '._-'):
                    continue

                if value in seen_values:
                    # Still add the match for replacement, but don't flag as new
                    pass
                seen_values.add(value)

                matches.append(PIIMatch(
                    start=start,
                    end=end,
                    raw_value=value,
                    pii_type=self.pii_type,
                    confidence=0.85,
                ))
        return matches
