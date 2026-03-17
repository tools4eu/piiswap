"""Generate consistent anonymization tokens."""

from piiswap.store.database import MappingStore

# Token prefixes per PII type
TOKEN_PREFIXES = {
    "email": "ANONEMAIL",
    "phone": "ANONPHONE",
    "iban": "ANONIBAN",
    "apikey": "ANONKEY",
    "password": "ANONPASS",
    "username": "ANONUSER",
    "firstname": "ANONFIRST",
    "lastname": "ANONLAST",
    "address": "ANONADDR",
    "hostname": "ANONHOST",
    "filepath_user": "ANONUSER",  # Same prefix as username (entity resolution links them)
    "name": "ANONNAME",
    "social_handle": "ANONHANDLE",
}


class TokenGenerator:
    """Generates sequential, type-prefixed anonymization tokens."""

    def __init__(self, store: MappingStore, case_id: str):
        self.store = store
        self.case_id = case_id

    def generate(self, pii_type: str) -> str:
        """Generate next token for the given PII type.

        Returns tokens like ANONEMAIL001, ANONUSER042, etc.
        Tokens never contain special characters (safe for XML, SQL, JSON).
        """
        prefix = TOKEN_PREFIXES.get(pii_type, "ANONUNK")
        num = self.store.next_token_number(pii_type, self.case_id)
        return f"{prefix}{num:03d}"
