"""Tests for EmailDetector.

Covers:
- Standard email detection (user@domain.com)
- Subdomain emails (user@mail.domain.com)
- Rejection of malformed addresses (just@, @domain, plain text)
"""

import pytest

from piiswap.detectors.email import EmailDetector


@pytest.fixture
def detector() -> EmailDetector:
    return EmailDetector()


# ---------------------------------------------------------------------------
# Positive cases: should be detected
# ---------------------------------------------------------------------------

def test_simple_email_detected(detector: EmailDetector) -> None:
    matches = detector.detect("Contact me at user@domain.com for details.")
    assert len(matches) == 1
    assert matches[0].raw_value == "user@domain.com"
    assert matches[0].pii_type == "email"


def test_email_with_plus_tag_detected(detector: EmailDetector) -> None:
    matches = detector.detect("Send to john+spam@example.com please.")
    assert len(matches) == 1
    assert matches[0].raw_value == "john+spam@example.com"


def test_email_with_dots_in_localpart_detected(detector: EmailDetector) -> None:
    matches = detector.detect("Reply to john.doe@company.org")
    assert len(matches) == 1
    assert matches[0].raw_value == "john.doe@company.org"


def test_email_with_subdomain_detected(detector: EmailDetector) -> None:
    matches = detector.detect("user@mail.domain.com sent an email.")
    assert len(matches) == 1
    assert matches[0].raw_value == "user@mail.domain.com"


def test_email_with_deep_subdomain_detected(detector: EmailDetector) -> None:
    matches = detector.detect("Forwarded from alice@smtp.internal.corp.be")
    assert len(matches) == 1
    assert matches[0].raw_value == "alice@smtp.internal.corp.be"


def test_email_with_numbers_in_domain_detected(detector: EmailDetector) -> None:
    matches = detector.detect("support@example2.io")
    assert len(matches) == 1
    assert matches[0].raw_value == "support@example2.io"


def test_uppercase_email_detected(detector: EmailDetector) -> None:
    # Email regex is case-sensitive by default, but real emails may be mixed-case
    matches = detector.detect("ADMIN@COMPANY.COM")
    assert len(matches) == 1
    assert matches[0].raw_value == "ADMIN@COMPANY.COM"


def test_multiple_emails_in_text_all_detected(detector: EmailDetector) -> None:
    text = "From: alice@example.com To: bob@example.org CC: carol@test.net"
    matches = detector.detect(text)
    raw_values = {m.raw_value for m in matches}
    assert "alice@example.com" in raw_values
    assert "bob@example.org" in raw_values
    assert "carol@test.net" in raw_values


def test_email_confidence_is_high(detector: EmailDetector) -> None:
    matches = detector.detect("contact@example.com")
    assert matches[0].confidence >= 0.9


def test_match_spans_are_correct(detector: EmailDetector) -> None:
    text = "Email: user@domain.com."
    matches = detector.detect(text)
    assert len(matches) == 1
    extracted = text[matches[0].start:matches[0].end]
    assert extracted == "user@domain.com"


# ---------------------------------------------------------------------------
# Negative cases: should NOT be detected
# ---------------------------------------------------------------------------

def test_at_sign_alone_not_detected(detector: EmailDetector) -> None:
    matches = detector.detect("just@ is not an email")
    assert len(matches) == 0


def test_domain_alone_not_detected(detector: EmailDetector) -> None:
    matches = detector.detect("@domain.com is not an email")
    assert len(matches) == 0


def test_plain_text_not_detected(detector: EmailDetector) -> None:
    matches = detector.detect("This is a plain sentence with no email address.")
    assert len(matches) == 0


def test_at_inside_word_not_detected(detector: EmailDetector) -> None:
    # No local part — should not match
    matches = detector.detect("Contact the @support team.")
    assert len(matches) == 0


def test_ip_address_not_detected_as_email(detector: EmailDetector) -> None:
    matches = detector.detect("Server at 192.168.1.1 is up.")
    assert len(matches) == 0


def test_hash_not_detected_as_email(detector: EmailDetector) -> None:
    sha256 = "a" * 64
    matches = detector.detect(f"Hash: {sha256}")
    assert len(matches) == 0
