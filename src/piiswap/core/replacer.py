"""Replacement engine: applies PII→token substitutions using flashtext."""

from typing import List, Optional

from flashtext import KeywordProcessor

from piiswap.store.database import MappingStore


class Replacer:
    """Performs text replacement in both directions using flashtext.

    For anonymization: raw_value → token
    For de-anonymization: token → raw_value
    """

    def __init__(self, store: MappingStore, case_id: str):
        self.store = store
        self.case_id = case_id

    def build_anonymize_processor(self) -> KeywordProcessor:
        """Build a flashtext processor: raw_value → token."""
        kp = KeywordProcessor(case_sensitive=True)
        # Treat URL path separators and backslashes as word boundaries so that
        # a username inside a profile URL like instagram.com/tom.doe is matched
        # when the stored raw_value is just "tom.doe".
        kp.non_word_boundaries -= {'/', '\\'}
        mappings = self.store.get_all_mappings(self.case_id)

        # Sort by length descending so longer matches take priority
        mappings.sort(key=lambda m: len(m["raw_value"]), reverse=True)

        for m in mappings:
            raw = m["raw_value"]
            token = m["token"]
            kp.add_keyword(raw, token)
            # Also add common case variants
            if raw[0].islower():
                kp.add_keyword(raw.capitalize(), token)
            elif raw[0].isupper() and not raw.isupper():
                kp.add_keyword(raw.lower(), token)

        return kp

    def build_deanonymize_processor(
        self, only_types: Optional[List[str]] = None
    ) -> KeywordProcessor:
        """Build a flashtext processor: token → raw_value.

        Args:
            only_types: If provided, only include token→value entries for
                        mappings whose pii_type is in this list.
        """
        kp = KeywordProcessor(case_sensitive=True)
        # Mirror the anonymize processor: keep URL path separators as word
        # boundaries so tokens inside paths are matched during de-anonymization.
        kp.non_word_boundaries -= {'/', '\\'}

        if only_types is not None:
            mappings = self.store.get_mappings_by_types(self.case_id, list(only_types))
        else:
            mappings = self.store.get_all_mappings(self.case_id)

        for m in mappings:
            kp.add_keyword(m["token"], m["raw_value"])

        return kp

    def anonymize_text(self, text: str) -> str:
        """Replace all known PII in text with tokens."""
        kp = self.build_anonymize_processor()
        return kp.replace_keywords(text)

    def deanonymize_text(self, text: str, only_types: Optional[List[str]] = None) -> str:
        """Replace tokens in text with original PII values.

        Args:
            text: Text containing anonymization tokens.
            only_types: If provided, only restore tokens for these PII types.
                        Tokens for other types are left as-is.
        """
        kp = self.build_deanonymize_processor(only_types=only_types)
        return kp.replace_keywords(text)
