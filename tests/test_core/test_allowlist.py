"""Tests for AllowlistFilter.

Covers:
- Built-in protection: IPv4 addresses, SHA256 hashes, timestamps, MITRE ATT&CK IDs
- Custom domain allowlisting: email addresses on allowlisted domains
- Custom value allowlisting: exact-match custom values
- Behaviour when no allowlist entries exist (no false exclusions)
"""

import pytest

from piiswap.core.allowlist import AllowlistFilter
from piiswap.detectors.base import PIIMatch
from piiswap.store.database import MappingStore


CASE_ID = "TEST-ALLOWLIST"


@pytest.fixture
def store(tmp_path) -> MappingStore:
    db = MappingStore(tmp_path / "test.db")
    db.open()
    yield db
    db.close()


@pytest.fixture
def allowlist(store: MappingStore) -> AllowlistFilter:
    return AllowlistFilter(store, CASE_ID)


def _make_match(raw_value: str, pii_type: str = "email", start: int = 0) -> PIIMatch:
    return PIIMatch(
        start=start,
        end=start + len(raw_value),
        raw_value=raw_value,
        pii_type=pii_type,
    )


def _filter(allowlist: AllowlistFilter, match: PIIMatch, text: str = "") -> bool:
    """Return True if the match was REMOVED (i.e., is allowlisted)."""
    result = allowlist.filter([match], text or match.raw_value)
    return len(result) == 0


# ---------------------------------------------------------------------------
# Built-in: IPv4 addresses
# ---------------------------------------------------------------------------

def test_ipv4_private_is_protected(allowlist: AllowlistFilter) -> None:
    text = "Connection from 192.168.1.1"
    match = _make_match("192.168.1.1", pii_type="hostname", start=16)
    assert _filter(allowlist, match, text)


def test_ipv4_public_is_protected(allowlist: AllowlistFilter) -> None:
    text = "C2 at 8.8.8.8"
    match = _make_match("8.8.8.8", pii_type="hostname", start=6)
    assert _filter(allowlist, match, text)


def test_ipv4_value_fullmatch_is_protected(allowlist: AllowlistFilter) -> None:
    # Even if the text context is minimal, the value itself matches IPv4 pattern
    match = _make_match("10.0.0.1", pii_type="hostname")
    assert _filter(allowlist, match, "10.0.0.1")


# ---------------------------------------------------------------------------
# Built-in: cryptographic hashes
# ---------------------------------------------------------------------------

def test_sha256_hash_is_protected(allowlist: AllowlistFilter) -> None:
    sha256 = "a" * 64
    match = _make_match(sha256, pii_type="apikey")
    assert _filter(allowlist, match, sha256)


def test_md5_hash_is_protected(allowlist: AllowlistFilter) -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert len(md5) == 32
    match = _make_match(md5, pii_type="apikey")
    assert _filter(allowlist, match, md5)


def test_sha1_hash_is_protected(allowlist: AllowlistFilter) -> None:
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert len(sha1) == 40
    match = _make_match(sha1, pii_type="apikey")
    assert _filter(allowlist, match, sha1)


# ---------------------------------------------------------------------------
# Built-in: timestamps
# ---------------------------------------------------------------------------

def test_iso_timestamp_is_protected(allowlist: AllowlistFilter) -> None:
    ts = "2025-03-17T14:30:00Z"
    text = f"Event at {ts} UTC"
    match = _make_match(ts, pii_type="unknown", start=9)
    assert _filter(allowlist, match, text)


def test_iso_timestamp_without_tz_is_protected(allowlist: AllowlistFilter) -> None:
    ts = "2025-03-17T14:30:00"
    match = _make_match(ts, pii_type="unknown")
    assert _filter(allowlist, match, ts)


def test_syslog_timestamp_is_protected(allowlist: AllowlistFilter) -> None:
    ts = "Mar 17 14:30:00"
    text = f"{ts} sshd[1234]: Accepted password"
    match = _make_match(ts, pii_type="unknown", start=0)
    assert _filter(allowlist, match, text)


# ---------------------------------------------------------------------------
# Built-in: MITRE ATT&CK IDs
# ---------------------------------------------------------------------------

def test_mitre_technique_id_is_protected(allowlist: AllowlistFilter) -> None:
    text = "Technique T1078 was used."
    match = _make_match("T1078", pii_type="unknown", start=10)
    assert _filter(allowlist, match, text)


def test_mitre_subtechnique_id_is_protected(allowlist: AllowlistFilter) -> None:
    text = "Sub-technique T1078.003 detected."
    match = _make_match("T1078.003", pii_type="unknown", start=14)
    assert _filter(allowlist, match, text)


def test_mitre_lowercase_t_is_protected(allowlist: AllowlistFilter) -> None:
    match = _make_match("t1078", pii_type="unknown")
    assert _filter(allowlist, match, "t1078")


# ---------------------------------------------------------------------------
# Custom domain allowlisting
# ---------------------------------------------------------------------------

def test_email_on_allowlisted_domain_is_protected(store: MappingStore) -> None:
    store.add_allowlist("example.com", value_type="domain", case_id=CASE_ID)
    al = AllowlistFilter(store, CASE_ID)

    match = _make_match("analyst@example.com", pii_type="email")
    assert _filter(al, match, "analyst@example.com")


def test_email_on_non_allowlisted_domain_not_protected(store: MappingStore) -> None:
    store.add_allowlist("example.com", value_type="domain", case_id=CASE_ID)
    al = AllowlistFilter(store, CASE_ID)

    # Different domain should NOT be protected
    match = _make_match("suspect@evil.com", pii_type="email")
    assert not _filter(al, match, "suspect@evil.com")


def test_hostname_on_allowlisted_domain_is_protected(store: MappingStore) -> None:
    store.add_allowlist("company.be", value_type="domain", case_id=CASE_ID)
    al = AllowlistFilter(store, CASE_ID)

    match = _make_match("mail.company.be", pii_type="hostname")
    assert _filter(al, match, "mail.company.be")


# ---------------------------------------------------------------------------
# Custom exact-value allowlisting
# ---------------------------------------------------------------------------

def test_custom_value_exact_match_is_protected(store: MappingStore) -> None:
    store.add_allowlist("john.doe", value_type="username", case_id=CASE_ID)
    al = AllowlistFilter(store, CASE_ID)

    match = _make_match("john.doe", pii_type="username")
    assert _filter(al, match, "john.doe")


def test_custom_value_case_insensitive_match(store: MappingStore) -> None:
    store.add_allowlist("ANALYST", value_type="username", case_id=CASE_ID)
    al = AllowlistFilter(store, CASE_ID)

    # Value stored as uppercase, match presented as lowercase
    match = _make_match("analyst", pii_type="username")
    assert _filter(al, match, "analyst")


def test_non_allowlisted_value_passes_through(allowlist: AllowlistFilter) -> None:
    # A real PII value with no built-in or custom protection should NOT be filtered
    match = _make_match("suspect@criminal.com", pii_type="email")
    result = allowlist.filter([match], "suspect@criminal.com")
    assert len(result) == 1
    assert result[0].raw_value == "suspect@criminal.com"


def test_empty_text_produces_no_crash(allowlist: AllowlistFilter) -> None:
    result = allowlist.filter([], "")
    assert result == []
