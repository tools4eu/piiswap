"""Allowlist: patterns and values that must NEVER be anonymized."""

import re
from typing import List

from piiswap.detectors.base import PIIMatch
from piiswap.store.database import MappingStore

# Built-in patterns that should never be anonymized in DFIR context
BUILTIN_PATTERNS = [
    # IPv4 addresses
    re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    # IPv6 (simplified)
    re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'),
    # MD5 hashes (exactly 32 hex chars)
    re.compile(r'\b[0-9a-fA-F]{32}\b'),
    # SHA1 hashes (exactly 40 hex chars)
    re.compile(r'\b[0-9a-fA-F]{40}\b'),
    # SHA256 hashes (exactly 64 hex chars)
    re.compile(r'\b[0-9a-fA-F]{64}\b'),
    # MITRE ATT&CK IDs
    re.compile(r'\b[Tt][Aa]?\d{4}(?:\.\d{3})?\b'),
    # ISO timestamps
    re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'),
    # Syslog timestamps
    re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b'),
    # Common protocols
    re.compile(r'\b(?:TCP|UDP|HTTP|HTTPS|SSH|RDP|FTP|DNS|SMTP|IMAP|POP3|TLS|SSL|NTP|SNMP|LDAP|SMB|ICMP)\b'),
    # Common process names
    re.compile(
        r'\b(?:svchost|explorer|cmd|powershell|rundll32|csrss|lsass|winlogon|'
        r'services|spoolsv|taskhost|conhost|dllhost|msiexec|wscript|cscript|'
        r'nginx|apache|httpd|sshd|systemd|cron|bash|sh|python|java|node)(?:\.exe)?\b',
        re.IGNORECASE,
    ),
    # Port numbers in context (e.g., :443, port 8080)
    re.compile(r'(?:port\s+|:)\d{1,5}\b', re.IGNORECASE),
    # MAC addresses
    re.compile(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b'),
]


class AllowlistFilter:
    """Filters out PII matches that should not be anonymized."""

    def __init__(self, store: MappingStore, case_id: str):
        self.store = store
        self.case_id = case_id
        self._custom_values: set = set()
        self._domain_values: set = set()
        self._load_custom()

    def _load_custom(self) -> None:
        entries = self.store.get_allowlist(self.case_id)
        self._custom_values = {e["value"].lower() for e in entries}
        self._domain_values = {e["value"].lower() for e in entries if e.get("value_type") == "domain"}

    def reload(self) -> None:
        self._load_custom()

    def filter(self, matches: List[PIIMatch], text: str) -> List[PIIMatch]:
        """Remove matches that overlap with allowlisted patterns."""
        filtered = []
        for match in matches:
            if self._is_allowed(match, text):
                continue
            filtered.append(match)
        return filtered

    def _is_allowed(self, match: PIIMatch, text: str) -> bool:
        value = match.raw_value

        # Check custom allowlist (exact match, case-insensitive)
        if value.lower() in self._custom_values:
            return True

        # Check domain allowlist: protect emails whose domain is allowlisted
        if self._domain_values and match.pii_type == "email" and "@" in value:
            email_domain = value.lower().split("@", 1)[1]
            if email_domain in self._domain_values:
                return True

        # Check domain allowlist: protect hostnames that end with an allowlisted domain
        if self._domain_values and match.pii_type == "hostname":
            hostname = value.lower().lstrip(".")
            for domain in self._domain_values:
                if hostname == domain or hostname.endswith("." + domain):
                    return True

        # Check if the matched region overlaps with any builtin pattern
        for pattern in BUILTIN_PATTERNS:
            for m in pattern.finditer(text):
                # If the allowlisted match fully contains or overlaps the PII match
                if m.start() <= match.start and match.end <= m.end():
                    return True
                # If the PII match value itself matches a builtin pattern
                if pattern.fullmatch(value):
                    return True

        return False
