"""Tests for FieldLabelDetector.

Covers:
- JSON "key": "value" patterns for name, username, and address fields
- key=value format (both quoted and unquoted)
- Dutch field labels (naam, gebruikersnaam, adres)
- Rejection of false-positive values (null, admin, 12345, etc.)
- Short value filtering (less than 3 characters)
"""

import pytest

from piiswap.detectors.fieldlabel import FieldLabelDetector


@pytest.fixture
def detector() -> FieldLabelDetector:
    return FieldLabelDetector()


def _raw_values(matches) -> list:
    return [m.raw_value for m in matches]


# ---------------------------------------------------------------------------
# JSON name fields
# ---------------------------------------------------------------------------

def test_json_display_name_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"display_name": "Tom V."')
    assert "Tom V." in _raw_values(matches)


def test_json_full_name_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"full_name": "Pieter Jansen"')
    assert "Pieter Jansen" in _raw_values(matches)


def test_json_subscriber_name_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"subscriber_name": "Maria De Smet"')
    assert "Maria De Smet" in _raw_values(matches)


def test_json_first_name_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"first_name": "Jan"')
    assert "Jan" in _raw_values(matches)


def test_json_last_name_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"last_name": "Vandenberghe"')
    assert "Vandenberghe" in _raw_values(matches)


def test_json_name_pii_type_is_name(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"display_name": "Tom V."')
    for m in matches:
        if m.raw_value == "Tom V.":
            assert m.pii_type == "name"
            break


# ---------------------------------------------------------------------------
# JSON username fields
# ---------------------------------------------------------------------------

def test_json_username_field_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"username": "darkuser"')
    assert "darkuser" in _raw_values(matches)


def test_json_login_name_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"login_name": "xX_shadow_Xx"')
    assert "xX_shadow_Xx" in _raw_values(matches)


def test_json_nickname_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"nick_name": "SilentBob"')
    assert "SilentBob" in _raw_values(matches)


def test_json_username_pii_type_is_username(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"username": "darkuser"')
    for m in matches:
        if m.raw_value == "darkuser":
            assert m.pii_type == "username"
            break


# ---------------------------------------------------------------------------
# JSON address fields
# ---------------------------------------------------------------------------

def test_json_address_field_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"address": "Kerkstraat 42"')
    assert "Kerkstraat 42" in _raw_values(matches)


def test_json_home_address_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"home_address": "Nieuwstraat 10"')
    assert "Nieuwstraat 10" in _raw_values(matches)


def test_json_address_pii_type_is_address(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"address": "Kerkstraat 42"')
    for m in matches:
        if m.raw_value == "Kerkstraat 42":
            assert m.pii_type == "address"
            break


# ---------------------------------------------------------------------------
# key=value format
# ---------------------------------------------------------------------------

def test_key_equals_value_unquoted_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect("display_name = Tom")
    assert "Tom" in _raw_values(matches)


def test_key_equals_value_quoted_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('display_name = "Jan Claes"')
    assert "Jan Claes" in _raw_values(matches)


def test_key_equals_username_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect("username = suspect007")
    assert "suspect007" in _raw_values(matches)


def test_key_equals_address_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('address = "Stationstraat 5"')
    assert "Stationstraat 5" in _raw_values(matches)


# ---------------------------------------------------------------------------
# Dutch field names
# ---------------------------------------------------------------------------

def test_dutch_naam_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"naam": "Pieter"')
    assert "Pieter" in _raw_values(matches)


def test_dutch_achternaam_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"achternaam": "De Wolf"')
    assert "De Wolf" in _raw_values(matches)


def test_dutch_gebruikersnaam_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"gebruikersnaam": "pietje_puk"')
    assert "pietje_puk" in _raw_values(matches)


def test_dutch_adres_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"adres": "Dorpstraat 99"')
    assert "Dorpstraat 99" in _raw_values(matches)


# ---------------------------------------------------------------------------
# False positives: should NOT be detected
# ---------------------------------------------------------------------------

def test_null_value_not_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"display_name": "null"')
    assert "null" not in _raw_values(matches)


def test_none_value_not_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"username": "none"')
    assert "none" not in _raw_values(matches)


def test_admin_value_not_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"username": "admin"')
    assert "admin" not in _raw_values(matches)


def test_numeric_value_not_detected(detector: FieldLabelDetector) -> None:
    # Pure numeric values (e.g., IDs) should be filtered
    matches = detector.detect('"username": "12345"')
    assert "12345" not in _raw_values(matches)


def test_empty_string_not_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"display_name": ""')
    assert "" not in _raw_values(matches)


def test_unknown_value_not_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"full_name": "unknown"')
    assert "unknown" not in _raw_values(matches)


def test_test_value_not_detected(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"display_name": "test"')
    assert "test" not in _raw_values(matches)


def test_short_value_under_3_chars_not_detected(detector: FieldLabelDetector) -> None:
    # Values shorter than 3 characters are filtered as likely abbreviations
    matches = detector.detect('"full_name": "AB"')
    assert "AB" not in _raw_values(matches)


def test_unrelated_field_not_detected(detector: FieldLabelDetector) -> None:
    # A JSON key with no known PII label should not produce matches
    matches = detector.detect('"status": "active"')
    assert len(matches) == 0


def test_confidence_is_set(detector: FieldLabelDetector) -> None:
    matches = detector.detect('"display_name": "Tom Claes"')
    for m in matches:
        if m.raw_value == "Tom Claes":
            assert 0.0 < m.confidence <= 1.0
            break
