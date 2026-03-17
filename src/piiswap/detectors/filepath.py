"""Detect usernames embedded in file paths."""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# Windows paths: C:\Users\<username>\...
WINDOWS_USER_PATH_RE = re.compile(
    r'[A-Za-z]:\\Users\\([^\\/:*?"<>|\s]+)\\',
    re.IGNORECASE,
)

# Linux/Mac paths: /home/<username>/...
LINUX_USER_PATH_RE = re.compile(
    r'/home/([^/\s]+)/',
)

# System accounts to exclude
SYSTEM_ACCOUNTS = {
    'public', 'default', 'all users', 'default user', 'administrator',
    'admin', 'root', 'system', 'local service', 'network service',
    'defaultapppool', 'guest', 'www-data', 'nobody', 'daemon',
}


class FilePathUserDetector(BaseDetector):
    pii_type = "filepath_user"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []

        for pattern in (WINDOWS_USER_PATH_RE, LINUX_USER_PATH_RE):
            for m in pattern.finditer(text):
                username = m.group(1)
                if username.lower() in SYSTEM_ACCOUNTS:
                    continue

                # Return the full path match but tag the username
                matches.append(PIIMatch(
                    start=m.start(1),
                    end=m.end(1),
                    raw_value=username,
                    pii_type=self.pii_type,
                    confidence=0.90,
                ))
        return matches
