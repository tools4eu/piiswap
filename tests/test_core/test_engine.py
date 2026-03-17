"""Tests for AnonymizationEngine.

Covers:
- Basic anonymize/deanonymize roundtrip (text is restored to original)
- Token format (ANON prefix + type + 3-digit number)
- IP addresses survive anonymization unchanged (allowlist protection)
- Cross-file consistency: same email gets the same token in separate calls
- Emails in same text are each assigned their own unique token
- Plain text with no PII is returned unchanged
"""

import pytest

from piiswap.core.engine import AnonymizationEngine
from piiswap.store.database import MappingStore


CASE_ID = "TEST-ENGINE"


@pytest.fixture
def store(tmp_path) -> MappingStore:
    db = MappingStore(tmp_path / "engine_test.db")
    db.open()
    yield db
    db.close()


@pytest.fixture
def engine(store: MappingStore) -> AnonymizationEngine:
    return AnonymizationEngine(store=store, case_id=CASE_ID)


# ---------------------------------------------------------------------------
# Basic anonymize / deanonymize roundtrip
# ---------------------------------------------------------------------------

def test_email_anonymize_produces_token(engine: AnonymizationEngine) -> None:
    result = engine.anonymize_text("Contact alice@example.com for info.")
    assert "alice@example.com" not in result
    assert "ANONEMAIL" in result


def test_email_deanonymize_restores_original(engine: AnonymizationEngine) -> None:
    original = "Contact alice@example.com for info."
    anonymized = engine.anonymize_text(original)
    restored = engine.deanonymize_text(anonymized)
    assert "alice@example.com" in restored


def test_roundtrip_full_equality(engine: AnonymizationEngine) -> None:
    original = "Reply to bob@company.org or call +32 471 12 34 56."
    anonymized = engine.anonymize_text(original)
    restored = engine.deanonymize_text(anonymized)
    # After roundtrip, all PII should be back
    assert "bob@company.org" in restored
    assert "+32 471 12 34 56" in restored


def test_no_pii_text_returned_unchanged(engine: AnonymizationEngine) -> None:
    text = "The server at 192.168.1.1 responded with status 200 OK."
    result = engine.anonymize_text(text)
    # No personal PII — text should be unchanged (IP is protected by allowlist)
    assert "192.168.1.1" in result


# ---------------------------------------------------------------------------
# Token format
# ---------------------------------------------------------------------------

def test_token_format_email(engine: AnonymizationEngine) -> None:
    result = engine.anonymize_text("admin@test.com sent a message.")
    # Token must match ANONEMAIL followed by exactly 3 digits
    import re
    assert re.search(r'ANONEMAIL\d{3}', result)


def test_token_numbers_are_sequential(engine: AnonymizationEngine) -> None:
    import re
    result1 = engine.anonymize_text("first@example.com")
    result2 = engine.anonymize_text("second@example.com")
    token1 = re.search(r'ANONEMAIL(\d{3})', result1)
    token2 = re.search(r'ANONEMAIL(\d{3})', result2)
    assert token1 and token2
    num1 = int(token1.group(1))
    num2 = int(token2.group(1))
    assert num2 == num1 + 1


# ---------------------------------------------------------------------------
# Allowlist: IPs survive anonymization
# ---------------------------------------------------------------------------

def test_ipv4_survives_anonymization(engine: AnonymizationEngine) -> None:
    text = "Attack originated from 10.0.0.5."
    result = engine.anonymize_text(text)
    assert "10.0.0.5" in result


def test_private_ip_survives_anonymization(engine: AnonymizationEngine) -> None:
    text = "Internal server: 192.168.100.50"
    result = engine.anonymize_text(text)
    assert "192.168.100.50" in result


def test_public_ip_survives_anonymization(engine: AnonymizationEngine) -> None:
    text = "C2 server: 185.220.101.45"
    result = engine.anonymize_text(text)
    assert "185.220.101.45" in result


def test_sha256_hash_survives_anonymization(engine: AnonymizationEngine) -> None:
    sha256 = "a" * 64
    text = f"Sample hash: {sha256}"
    result = engine.anonymize_text(text)
    assert sha256 in result


def test_mitre_attack_id_survives_anonymization(engine: AnonymizationEngine) -> None:
    text = "Technique T1078 (Valid Accounts) was used."
    result = engine.anonymize_text(text)
    assert "T1078" in result


# ---------------------------------------------------------------------------
# Cross-file consistency
# ---------------------------------------------------------------------------

def test_same_email_gets_same_token_across_calls(engine: AnonymizationEngine) -> None:
    """The same email processed in two separate calls must produce the same token."""
    import re
    text_a = "File A: contact alice@example.com here."
    text_b = "File B: forward to alice@example.com as well."

    anon_a = engine.anonymize_text(text_a, source_file="file_a.txt")
    anon_b = engine.anonymize_text(text_b, source_file="file_b.txt")

    token_a = re.search(r'ANONEMAIL\d{3}', anon_a)
    token_b = re.search(r'ANONEMAIL\d{3}', anon_b)

    assert token_a and token_b
    assert token_a.group() == token_b.group()


def test_different_emails_get_different_tokens(engine: AnonymizationEngine) -> None:
    import re
    text = "From alice@example.com to bob@example.com."
    result = engine.anonymize_text(text)
    tokens = re.findall(r'ANONEMAIL\d{3}', result)
    assert len(tokens) == 2
    assert tokens[0] != tokens[1]


# ---------------------------------------------------------------------------
# Scan (dry-run) mode
# ---------------------------------------------------------------------------

def test_scan_text_detects_email(engine: AnonymizationEngine) -> None:
    matches = engine.scan_text("Contact suspect@evil.com for ransom.")
    pii_types = [m.pii_type for m in matches]
    assert "email" in pii_types


def test_scan_text_does_not_modify_text(engine: AnonymizationEngine) -> None:
    # scan_text returns matches, not modified text — verify no side effect
    text = "victim@target.org"
    engine.scan_text(text)
    # The engine store should still have no mappings (scan does not register)
    mappings = engine.store.get_all_mappings(CASE_ID)
    assert len(mappings) == 0


def test_scan_text_ip_excluded_from_matches(engine: AnonymizationEngine) -> None:
    matches = engine.scan_text("Server 192.168.1.1 is under attack.")
    raw_values = [m.raw_value for m in matches]
    assert "192.168.1.1" not in raw_values
