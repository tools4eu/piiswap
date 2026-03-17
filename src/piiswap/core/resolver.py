"""Entity resolution: link related PII to the same person/entity."""

import re
from typing import Optional

from piiswap.store.database import MappingStore


class EntityResolver:
    """Links related PII values to the same entity.

    Resolution rules (in order of confidence):
    1. Exact match: raw_value already mapped → reuse entity_id
    2. Email → username: extract local part, link if username exists
    3. Username → name parts: split on [._-], link firstname/lastname
    4. Filepath user → username: link if matching username exists
    5. Manual override via CLI
    """

    def __init__(self, store: MappingStore, case_id: str):
        self.store = store
        self.case_id = case_id
        self._entity_counter = 0
        self._init_counter()

    def _init_counter(self) -> None:
        """Initialize entity counter from existing entities."""
        row = self.store.conn.execute(
            "SELECT COUNT(*) as cnt FROM entities WHERE entity_type = 'person'"
        ).fetchone()
        self._entity_counter = row["cnt"] if row else 0

    def _next_entity_id(self) -> str:
        self._entity_counter += 1
        return f"PERSON{self._entity_counter:03d}"

    def resolve(self, pii_type: str, raw_value: str, source_file: str = "") -> str:
        """Find or create an entity for this PII value.

        Returns the entity_id (e.g., 'PERSON-001').
        """
        # Rule 1: Exact match — already seen this value?
        existing = self.store.find_entity_by_raw(raw_value, self.case_id)
        if existing:
            return existing

        # Rule 2: Email → extract local part → check username
        if pii_type == "email":
            entity_id = self._resolve_email(raw_value)
            if entity_id:
                return entity_id

        # Rule 3: Username → check if it matches email local parts or name parts
        if pii_type in ("username", "filepath_user"):
            entity_id = self._resolve_username(raw_value)
            if entity_id:
                return entity_id

        # Rule 4: Name → check if it appears in a known username/email
        if pii_type in ("firstname", "lastname"):
            entity_id = self._resolve_name_part(raw_value)
            if entity_id:
                return entity_id

        # No match found → create new entity
        entity_id = self._next_entity_id()
        self.store.create_entity(entity_id, "person")
        return entity_id

    def _resolve_email(self, email: str) -> Optional[str]:
        """Extract local part from email and check if matching username exists."""
        local_part = email.split("@")[0] if "@" in email else None
        if not local_part:
            return None

        # Check if this local part exists as a username
        entity_id = self.store.find_entity_by_raw(local_part, self.case_id)
        if entity_id:
            return entity_id

        # Check if any existing email shares this local part
        rows = self.store.conn.execute(
            "SELECT entity_id, raw_value FROM mappings WHERE pii_type = 'email' AND case_id = ?",
            (self.case_id,),
        ).fetchall()
        for row in rows:
            existing_local = row["raw_value"].split("@")[0]
            if existing_local.lower() == local_part.lower():
                return row["entity_id"]

        return None

    def _resolve_username(self, username: str) -> Optional[str]:
        """Check if username matches email local parts or name combinations."""
        username_lower = username.lower()

        # Check email local parts
        rows = self.store.conn.execute(
            "SELECT entity_id, raw_value FROM mappings WHERE pii_type = 'email' AND case_id = ?",
            (self.case_id,),
        ).fetchall()
        for row in rows:
            local_part = row["raw_value"].split("@")[0].lower()
            if local_part == username_lower:
                return row["entity_id"]

        # Check if username can be split into known firstname + lastname
        parts = re.split(r'[._\-]', username_lower)
        if len(parts) >= 2:
            for part in parts:
                entity_id = self._find_name_entity(part)
                if entity_id:
                    return entity_id

        return None

    def _resolve_name_part(self, name: str) -> Optional[str]:
        """Check if this name appears as part of a known username."""
        name_lower = name.lower()

        # Check all usernames for this name as a component
        rows = self.store.conn.execute(
            "SELECT entity_id, raw_value FROM mappings WHERE pii_type IN ('username', 'filepath_user') AND case_id = ?",
            (self.case_id,),
        ).fetchall()
        for row in rows:
            parts = re.split(r'[._\-]', row["raw_value"].lower())
            if name_lower in parts:
                return row["entity_id"]

        return None

    def _find_name_entity(self, name_part: str) -> Optional[str]:
        """Find an entity that has this name part as a firstname or lastname."""
        row = self.store.conn.execute(
            "SELECT entity_id FROM mappings WHERE LOWER(raw_value) = ? AND pii_type IN ('firstname', 'lastname') AND case_id = ?",
            (name_part, self.case_id),
        ).fetchone()
        return row["entity_id"] if row else None

    def link_entities(self, entity_id_keep: str, entity_id_merge: str) -> None:
        """Manually merge two entities (for CLI 'link' command)."""
        self.store.conn.execute(
            "UPDATE mappings SET entity_id = ? WHERE entity_id = ? AND case_id = ?",
            (entity_id_keep, entity_id_merge, self.case_id),
        )
        self.store.conn.execute(
            "DELETE FROM entities WHERE entity_id = ?",
            (entity_id_merge,),
        )
        self.store.conn.commit()
