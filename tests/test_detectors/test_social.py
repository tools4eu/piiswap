"""Tests for SocialHandleDetector.

Covers:
- @handles (Twitter/Instagram/Telegram style)
- Reddit u/ handles
- Social media profile URLs (instagram.com, twitter.com/x.com)
- Discord old-style tags (user#1234)
- JSON/CSV social field labels (screen_name, twitter_username, etc.)
- Rejection of false-positive handles (@everyone, @admin)
- Rejection of purely numeric handles
"""

import pytest

from piiswap.detectors.social import SocialHandleDetector


@pytest.fixture
def detector() -> SocialHandleDetector:
    return SocialHandleDetector()


# ---------------------------------------------------------------------------
# @handle detection
# ---------------------------------------------------------------------------

def test_at_handle_simple_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Follow @john_doe on Twitter.")
    values = [m.raw_value for m in matches]
    assert "@john_doe" in values


def test_at_handle_mixed_case_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Check @TomVDB_official for updates.")
    values = [m.raw_value for m in matches]
    assert "@TomVDB_official" in values


def test_at_handle_with_dots_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Sent from @jan.de.vries")
    values = [m.raw_value for m in matches]
    assert "@jan.de.vries" in values


def test_at_handle_at_line_start_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("@realuser posted something.")
    values = [m.raw_value for m in matches]
    assert "@realuser" in values


def test_at_handle_pii_type(detector: SocialHandleDetector) -> None:
    matches = detector.detect("@john_doe")
    assert all(m.pii_type == "social_handle" for m in matches)


def test_multiple_at_handles_all_detected(detector: SocialHandleDetector) -> None:
    text = "Conversation between @alice and @bob_99"
    matches = detector.detect(text)
    values = [m.raw_value for m in matches]
    assert "@alice" in values
    assert "@bob_99" in values


# ---------------------------------------------------------------------------
# Reddit u/ handles
# ---------------------------------------------------------------------------

def test_reddit_u_handle_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Posted by u/crypto_user on Reddit.")
    values = [m.raw_value for m in matches]
    assert "u/crypto_user" in values


def test_reddit_u_handle_at_start_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("u/dark_trader started the thread.")
    values = [m.raw_value for m in matches]
    assert "u/dark_trader" in values


# ---------------------------------------------------------------------------
# Profile URL detection
# ---------------------------------------------------------------------------

def test_instagram_url_username_detected(detector: SocialHandleDetector) -> None:
    text = "Profile: https://instagram.com/suspect_username"
    matches = detector.detect(text)
    values = [m.raw_value for m in matches]
    assert "suspect_username" in values


def test_twitter_url_username_detected(detector: SocialHandleDetector) -> None:
    text = "Twitter: https://twitter.com/hackerman"
    matches = detector.detect(text)
    values = [m.raw_value for m in matches]
    assert "hackerman" in values


def test_x_com_url_username_detected(detector: SocialHandleDetector) -> None:
    text = "X: https://x.com/realuser99"
    matches = detector.detect(text)
    values = [m.raw_value for m in matches]
    assert "realuser99" in values


def test_tiktok_url_username_detected(detector: SocialHandleDetector) -> None:
    text = "TikTok: https://tiktok.com/@funny_clips"
    matches = detector.detect(text)
    values = [m.raw_value for m in matches]
    assert "funny_clips" in values


def test_facebook_url_username_detected(detector: SocialHandleDetector) -> None:
    text = "FB: https://facebook.com/john.doe.Belgium"
    matches = detector.detect(text)
    values = [m.raw_value for m in matches]
    assert "john.doe.Belgium" in values


def test_instagram_system_paths_not_detected(detector: SocialHandleDetector) -> None:
    # /p/, /reel/, /stories/ are content paths, not usernames
    matches = detector.detect("https://instagram.com/p/ABC123xyz/")
    # The path component "ABC123xyz" could match but the prefix /p/ should block it
    values = [m.raw_value for m in matches]
    assert "p" not in values


def test_twitter_status_path_not_detected(detector: SocialHandleDetector) -> None:
    # /status/ is a tweet path, not a username
    matches = detector.detect("https://twitter.com/status/123456789012345678")
    values = [m.raw_value for m in matches]
    assert "status" not in values


# ---------------------------------------------------------------------------
# Discord old-style tag: user#1234
# ---------------------------------------------------------------------------

def test_discord_tag_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Discord: user#1234")
    values = [m.raw_value for m in matches]
    assert "user#1234" in values


def test_discord_tag_with_mixed_name_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Contact DarkKnight99#5678 on Discord.")
    values = [m.raw_value for m in matches]
    assert "DarkKnight99#5678" in values


# ---------------------------------------------------------------------------
# JSON/CSV social field labels
# ---------------------------------------------------------------------------

def test_screen_name_field_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect('"screen_name": "darkuser99"')
    values = [m.raw_value for m in matches]
    assert "darkuser99" in values


def test_twitter_username_field_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect('"twitter_username": "johndoe_be"')
    values = [m.raw_value for m in matches]
    assert "johndoe_be" in values


def test_snapchat_field_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect('"snapchat_username": "snap.user"')
    values = [m.raw_value for m in matches]
    assert "snap.user" in values


# ---------------------------------------------------------------------------
# False positives: should NOT be detected
# ---------------------------------------------------------------------------

def test_at_everyone_not_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Hey @everyone please read this.")
    values = [m.raw_value for m in matches]
    assert "@everyone" not in values


def test_at_admin_not_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Notify @admin immediately.")
    values = [m.raw_value for m in matches]
    assert "@admin" not in values


def test_at_support_not_detected(detector: SocialHandleDetector) -> None:
    matches = detector.detect("Contact @support for help.")
    values = [m.raw_value for m in matches]
    assert "@support" not in values


def test_numeric_only_handle_not_detected(detector: SocialHandleDetector) -> None:
    # Pure numeric handles are IOCs (platform IDs), not personal handles
    matches = detector.detect("@12345678")
    values = [m.raw_value for m in matches]
    assert "@12345678" not in values


def test_programming_decorator_not_detected(detector: SocialHandleDetector) -> None:
    # @override, @deprecated, @property are Java/Python annotations, not handles
    matches = detector.detect("@override\npublic void method() {}")
    values = [m.raw_value for m in matches]
    assert "@override" not in values


def test_at_in_email_not_detected_as_handle(detector: SocialHandleDetector) -> None:
    # An email should not produce a spurious @handle match for the local part
    matches = detector.detect("john@example.com")
    # The AT_HANDLE_RE requires that the match is NOT followed by another @
    # and requires alphanumeric/letter start — email local parts followed by @domain
    # should be excluded by the "not followed by alnum or @" rule.
    # Verify no match consumes "john" as a handle here.
    for m in matches:
        assert m.pii_type != "social_handle" or "@" not in m.raw_value or "example.com" in m.raw_value
