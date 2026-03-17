"""Snapchat production data detector.

Parses Snapchat's legal production CSV format (subscriber_info.csv,
public_profile.csv, ip_data.csv) and extracts PII from known column
positions. Handles:

- Target username header: 'Target username "amerrr.070"'
- subscriber_info columns: username, email_address, pending_email_address,
  phone_number, pending_phone_number, former_phone_number, display_name
- Change history: USERNAME, DISPLAY_NAME, PHONE action rows (old_value, new_value)
- Username history: old_value, new_value pairs
- public_profile columns: display_name
"""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# --- Header pattern ---
TARGET_USERNAME_RE = re.compile(
    r'Target username\s+"+"?([^"]+)"+"?',
    re.IGNORECASE,
)

# --- subscriber_info.csv data row ---
SUBSCRIBER_HEADER = (
    "username,email_address,email_status,pending_email_address,created,"
    "creation_ip,phone_number,phone_status,pending_phone_number,"
    "former_phone_number,display_name,status"
)

# --- Change history rows ---
CHANGE_HISTORY_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC),'
    r'(USERNAME|DISPLAY_NAME|PHONE),'
    r'([^,]*),'     # old_value
    r'([^,]*),'     # new_value
    r'(\w+)$',      # reason
    re.MULTILINE,
)

# --- Username history rows ---
USERNAME_HISTORY_RE = re.compile(
    r'^([A-Za-z][A-Za-z0-9._-]{1,30}),'
    r'([A-Za-z][A-Za-z0-9._-]{1,30}),'
    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)$',
    re.MULTILINE,
)

# Values to skip
_SKIP = {
    '', 'true', 'false', 'active', 'deleted', 'not enabled', 'sms',
    'username', 'email_address', 'phone_number', 'display_name',
    'old_value', 'new_value', 'timestamp', 'reason', 'action', 'date',
}


class SnapchatDetector(BaseDetector):
    """Detect PII in Snapchat legal production data files."""

    pii_type = "username"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        seen_spans = set()

        # 1. Target username header
        for m in TARGET_USERNAME_RE.finditer(text):
            val = m.group(1).strip()
            if val and val.lower() not in _SKIP:
                matches.append(self._match(m.start(1), m.end(1), val, "username", 0.95))

        # 2. subscriber_info data rows (after known header)
        self._parse_subscriber_rows(text, matches)

        # 3. Change history rows
        for m in CHANGE_HISTORY_RE.finditer(text):
            action = m.group(2)
            old_val = m.group(3).strip()
            new_val = m.group(4).strip()
            pii_type = self._action_to_type(action)

            if old_val and old_val.lower() not in _SKIP:
                matches.append(self._match(m.start(3), m.end(3), old_val, pii_type, 0.92))
            if new_val and new_val.lower() not in _SKIP:
                matches.append(self._match(m.start(4), m.end(4), new_val, pii_type, 0.92))

        # 4. Username history rows
        for m in USERNAME_HISTORY_RE.finditer(text):
            old_u = m.group(1)
            new_u = m.group(2)
            if old_u.lower() not in _SKIP:
                matches.append(self._match(m.start(1), m.end(1), old_u, "username", 0.90))
            if new_u.lower() not in _SKIP:
                matches.append(self._match(m.start(2), m.end(2), new_u, "username", 0.90))

        # Deduplicate by span
        unique = []
        for match in matches:
            key = (match.start, match.end)
            if key not in seen_spans:
                seen_spans.add(key)
                unique.append(match)

        return unique

    def _parse_subscriber_rows(self, text: str, matches: list) -> None:
        """Parse subscriber_info CSV rows using the known header."""
        header_pos = text.find(SUBSCRIBER_HEADER)
        while header_pos != -1:
            newline = text.find("\n", header_pos)
            if newline == -1:
                break
            data_start = newline + 1
            data_end = text.find("\n", data_start)
            if data_end == -1:
                data_end = len(text)
            data_line = text[data_start:data_end].strip()
            if data_line and not data_line.startswith("-") and not data_line.startswith("="):
                self._extract_subscriber_fields(data_line, data_start, matches)
            header_pos = text.find(SUBSCRIBER_HEADER, data_end)

    def _extract_subscriber_fields(self, line: str, line_start: int, matches: list) -> None:
        """Extract PII fields from a subscriber_info data row.

        Column order:
        0: username, 1: email_address, 2: email_status (skip),
        3: pending_email_address, 4: created (skip), 5: creation_ip (skip),
        6: phone_number, 7: phone_status (skip), 8: pending_phone_number,
        9: former_phone_number, 10: display_name, 11: status (skip)
        """
        parts = line.split(",")
        if len(parts) < 11:
            return

        pii_columns = {
            0: "username",
            1: "email",
            3: "email",
            6: "phone",
            8: "phone",
            9: "phone",
            10: "name",
        }

        offset = 0
        for i, part in enumerate(parts):
            val = part.strip()
            if i in pii_columns and val and val.lower() not in _SKIP:
                pii_type = pii_columns[i]
                start = line_start + offset
                end = start + len(val)
                matches.append(self._match(start, end, val, pii_type, 0.93))
            offset += len(part) + 1

    @staticmethod
    def _action_to_type(action: str) -> str:
        return {
            "USERNAME": "username",
            "DISPLAY_NAME": "name",
            "PHONE": "phone",
        }.get(action, "username")

    def _match(self, start, end, value, pii_type, confidence):
        return PIIMatch(
            start=start,
            end=end,
            raw_value=value,
            pii_type=pii_type,
            confidence=confidence,
        )
