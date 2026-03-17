"""Detect social media handles, profile URLs, and display names.

Covers: Snapchat, Instagram, Twitter/X, Facebook, TikTok, Telegram,
        Discord, Reddit, LinkedIn, YouTube.

Design decisions:
- @handles and u/ handles → pii_type "social_handle" → anonymized
- Profile URLs with usernames → pii_type "social_handle" → anonymized
- Numeric platform IDs (Snap ID, FBID, Discord snowflake) are IOCs
  and are NOT matched here (they stay visible for correlation).
"""

import re
from typing import List

from piiswap.detectors.base import BaseDetector, PIIMatch

# ---------------------------------------------------------------------------
# 1. @handle patterns  (Twitter, Instagram, TikTok, Telegram, YouTube, Discord)
# ---------------------------------------------------------------------------
# Rules:
#   - Starts with @
#   - 1-30 alphanumeric + underscore + dot (platform-dependent, we use union)
#   - Must NOT be followed by another @ (would be an email)
#   - Must be preceded by whitespace, start-of-line, or punctuation
AT_HANDLE_RE = re.compile(
    r'(?:^|(?<=[\s,;:(\[{"\']))'   # lookbehind: start, whitespace or punctuation
    r'@([A-Za-z][A-Za-z0-9._]{0,29})'  # @handle (letter + up to 29 chars)
    r'(?![A-Za-z0-9@])',            # not followed by more alnum or @ (not email)
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# 2. Reddit u/username
# ---------------------------------------------------------------------------
REDDIT_HANDLE_RE = re.compile(
    r'(?:^|(?<=[\s,;:(\[{"\']))'
    r'u/([A-Za-z0-9_-]{3,20})'
    r'(?![A-Za-z0-9])',
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# 3. Social media profile URLs
# ---------------------------------------------------------------------------
# Match: https://platform.com/username or http://platform.com/username
# Captures the username portion from the URL path.
SOCIAL_URL_PATTERNS = [
    # Instagram: instagram.com/username (not /p/, /reel/, /stories/)
    re.compile(
        r'(?:https?://)?(?:www\.)?instagram\.com/(?!p/|reel/|stories/|explore/|accounts/)([A-Za-z0-9._]{1,30})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
    # Twitter/X: twitter.com/username or x.com/username (not /status/, /i/, /search)
    re.compile(
        r'(?:https?://)?(?:www\.)?(?:twitter|x)\.com/(?!status/|i/|search|hashtag|intent)([A-Za-z0-9_]{1,15})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
    # Facebook: facebook.com/username (not /groups/, /pages/, /events/)
    re.compile(
        r'(?:https?://)?(?:www\.)?facebook\.com/(?!groups/|pages/|events/|marketplace/|watch/)([A-Za-z0-9.]{1,50})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
    # TikTok: tiktok.com/@username
    re.compile(
        r'(?:https?://)?(?:www\.)?tiktok\.com/@([A-Za-z0-9._]{1,24})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
    # LinkedIn: linkedin.com/in/slug
    re.compile(
        r'(?:https?://)?(?:www\.)?linkedin\.com/in/([A-Za-z0-9-]{3,100})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
    # YouTube: youtube.com/@handle
    re.compile(
        r'(?:https?://)?(?:www\.)?youtube\.com/@([A-Za-z0-9._-]{1,30})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
    # Telegram: t.me/username
    re.compile(
        r'(?:https?://)?t\.me/(?!joinchat/|addstickers/|\+)([A-Za-z][A-Za-z0-9_]{4,31})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
    # Snapchat: snapchat.com/add/username
    re.compile(
        r'(?:https?://)?(?:www\.)?snapchat\.com/add/([A-Za-z][A-Za-z0-9._-]{2,14})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
    # Reddit: reddit.com/user/username
    re.compile(
        r'(?:https?://)?(?:www\.)?reddit\.com/u(?:ser)?/([A-Za-z0-9_-]{3,20})(?:\b|/|\?|$)',
        re.IGNORECASE,
    ),
]

# ---------------------------------------------------------------------------
# 4. JSON/CSV key-value patterns for social media fields
# ---------------------------------------------------------------------------
# Matches: "screen_name": "value", "display_name": "value", "snapchat_username": "value"
SOCIAL_FIELD_RE = re.compile(
    r'["\']?(?:'
    r'screen[_\s]?name|snap(?:chat)?[_\s]?(?:user(?:name)?|handle)'
    r'|(?:twitter|instagram|tiktok|telegram|discord|reddit|youtube|facebook|fb)[_\s]?(?:user(?:name)?|handle|name|screen[_\s]?name)'
    r'|user[_\s]?handle|social[_\s]?handle'
    r')'
    r'["\']?\s*[:=]\s*["\']?'
    r'([A-Za-z][A-Za-z0-9._-]{1,30})',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 5. Discord old-style: username#1234
# ---------------------------------------------------------------------------
DISCORD_TAG_RE = re.compile(
    r'\b([A-Za-z][A-Za-z0-9._-]{1,31})#(\d{4})\b'
)

# ---------------------------------------------------------------------------
# False positives: common handles/accounts that are not personal PII
# ---------------------------------------------------------------------------
HANDLE_FALSE_POSITIVES = {
    'everyone', 'here', 'channel', 'all', 'admin', 'support',
    'help', 'info', 'news', 'official', 'bot', 'status',
    'api', 'dev', 'docs', 'app', 'web', 'mail', 'team',
    'mention', 'param', 'type', 'nullable', 'override',
    'deprecated', 'property', 'interface', 'class', 'extends',
    'implements', 'abstract', 'static', 'return', 'import',
}


class SocialHandleDetector(BaseDetector):
    """Detect social media handles, profile URLs, and screen names."""

    pii_type = "social_handle"

    def detect(self, text: str) -> List[PIIMatch]:
        matches = []
        seen = set()

        # @handles
        for m in AT_HANDLE_RE.finditer(text):
            handle = m.group(1)
            if self._is_valid(handle):
                # Match the full @handle including the @
                matches.append(self._make_match(m.start(), m.end(), f"@{handle}"))
                seen.add(handle.lower())

        # Reddit u/handles
        for m in REDDIT_HANDLE_RE.finditer(text):
            handle = m.group(1)
            if handle.lower() not in seen and self._is_valid(handle):
                matches.append(self._make_match(m.start(), m.end(), f"u/{handle}"))
                seen.add(handle.lower())

        # Social media URLs
        for pattern in SOCIAL_URL_PATTERNS:
            for m in pattern.finditer(text):
                handle = m.group(1)
                if handle.lower() not in seen and self._is_valid(handle):
                    # Anonymize the username part only, keep the domain
                    matches.append(self._make_match(
                        m.start(1), m.end(1), handle, confidence=0.90,
                    ))
                    seen.add(handle.lower())

        # JSON/CSV social media fields
        for m in SOCIAL_FIELD_RE.finditer(text):
            value = m.group(1)
            if value.lower() not in seen and self._is_valid(value):
                matches.append(self._make_match(
                    m.start(1), m.end(1), value, confidence=0.85,
                ))
                seen.add(value.lower())

        # Discord old-style: user#1234
        for m in DISCORD_TAG_RE.finditer(text):
            username = m.group(1)
            full = f"{username}#{m.group(2)}"
            if full.lower() not in seen and self._is_valid(username):
                matches.append(self._make_match(
                    m.start(), m.end(), full, confidence=0.90,
                ))
                seen.add(full.lower())

        return matches

    def _is_valid(self, handle: str) -> bool:
        """Filter out false positives."""
        if handle.lower() in HANDLE_FALSE_POSITIVES:
            return False
        if len(handle) < 2:
            return False
        # Pure numeric = likely a platform ID (IOC), not a handle
        if handle.isdigit():
            return False
        return True

    def _make_match(self, start, end, value, confidence=0.88):
        return PIIMatch(
            start=start,
            end=end,
            raw_value=value,
            pii_type=self.pii_type,
            confidence=confidence,
        )
