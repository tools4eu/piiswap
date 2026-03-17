"""Tests for PhoneDetector.

Covers:
- International E.164 formats (+32 ..., +1 ...)
- Belgian local formats (0471 ..., 04/... , 02 ...)
- US parenthesis format ((555) 123-4567)
- Generic 10-digit format with separators (555-123-4567)
- Rejection of plain number sequences and hash/version contexts
"""

import pytest

from piiswap.detectors.phone import PhoneDetector


@pytest.fixture
def detector() -> PhoneDetector:
    return PhoneDetector()


# ---------------------------------------------------------------------------
# Positive cases: international formats
# ---------------------------------------------------------------------------

def test_belgian_international_format_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("Bel mij op +32 471 12 34 56.")
    assert len(matches) == 1
    assert "+32" in matches[0].raw_value
    assert matches[0].pii_type == "phone"


def test_us_international_format_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("Call +1-555-123-4567 after 5pm.")
    assert len(matches) == 1
    assert "+1" in matches[0].raw_value


def test_international_with_dots_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("Phone: +44.20.7946.0958")
    assert len(matches) == 1
    assert "+44" in matches[0].raw_value


def test_international_no_separator_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("GSM: +32471123456")
    assert len(matches) == 1


# ---------------------------------------------------------------------------
# Positive cases: Belgian local formats
# ---------------------------------------------------------------------------

def test_belgian_mobile_space_format_detected(detector: PhoneDetector) -> None:
    # 0471 12 34 56
    matches = detector.detect("GSM: 0471 12 34 56")
    assert len(matches) == 1
    assert "0471" in matches[0].raw_value


def test_belgian_landline_slash_format_detected(detector: PhoneDetector) -> None:
    # 04/123.45.67
    matches = detector.detect("Tel: 04/123.45.67")
    assert len(matches) == 1


def test_belgian_brussels_landline_detected(detector: PhoneDetector) -> None:
    # 02 123 45 67
    matches = detector.detect("Kantoor: 02 123 45 67")
    assert len(matches) == 1
    assert "02" in matches[0].raw_value


# ---------------------------------------------------------------------------
# Positive cases: generic formats
# ---------------------------------------------------------------------------

def test_us_parenthesis_format_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("Office: (555) 123-4567")
    assert len(matches) == 1
    assert "(555)" in matches[0].raw_value


def test_generic_dash_format_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("Fax: 555-123-4567")
    assert len(matches) == 1


def test_generic_dot_format_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("555.123.4567")
    assert len(matches) == 1


def test_pii_type_is_phone(detector: PhoneDetector) -> None:
    matches = detector.detect("+32 471 12 34 56")
    assert matches[0].pii_type == "phone"


def test_match_span_covers_full_number(detector: PhoneDetector) -> None:
    text = "Number: +32 471 12 34 56 end"
    matches = detector.detect(text)
    assert len(matches) == 1
    extracted = text[matches[0].start:matches[0].end]
    assert "+32" in extracted


# ---------------------------------------------------------------------------
# Negative cases: should NOT be detected
# ---------------------------------------------------------------------------

def test_plain_short_number_not_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("ID is 12345.")
    assert len(matches) == 0


def test_plain_integer_not_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("The answer is 42.")
    assert len(matches) == 0


def test_hash_context_suppresses_detection(detector: PhoneDetector) -> None:
    # False positive context: "hash" before numbers should suppress match
    matches = detector.detect("sha256 hash 1234567890123456")
    assert len(matches) == 0


def test_version_number_not_detected(detector: PhoneDetector) -> None:
    matches = detector.detect("version v1.234.567")
    assert len(matches) == 0


def test_ip_address_not_detected_as_phone(detector: PhoneDetector) -> None:
    matches = detector.detect("IP: 192.168.1.100")
    assert len(matches) == 0


def test_too_many_digits_not_detected(detector: PhoneDetector) -> None:
    # 20-digit string: exceeds max digit count of 15
    matches = detector.detect("+123456789012345678901")
    assert len(matches) == 0
