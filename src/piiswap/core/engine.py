"""Main orchestrator: ties together detection, resolution, tokenization, and replacement."""

import hashlib
import os
from pathlib import Path
from typing import List, Optional

from piiswap.adapters.base import FileAdapter, get_adapter
from piiswap.core.allowlist import AllowlistFilter
from piiswap.core.detector import DetectionCoordinator, get_default_detectors
from piiswap.core.replacer import Replacer
from piiswap.core.resolver import EntityResolver
from piiswap.core.tokenizer import TokenGenerator
from piiswap.detectors.base import PIIMatch
from piiswap.store.database import MappingStore


class AnonymizationEngine:
    """Main pipeline orchestrator for anonymization and de-anonymization."""

    def __init__(
        self,
        store: MappingStore,
        case_id: str,
        strict_names: bool = False,
        name_detector=None,
        address_detector=None,
        include_types: Optional[List[str]] = None,
        exclude_types: Optional[List[str]] = None,
        pii_columns: Optional[List[str]] = None,
        keep_columns: Optional[List[str]] = None,
    ):
        self.store = store
        self.case_id = case_id
        self.pii_columns = pii_columns
        self.keep_columns = keep_columns

        # Core components
        self.resolver = EntityResolver(store, case_id)
        self.tokenizer = TokenGenerator(store, case_id)
        self.allowlist = AllowlistFilter(store, case_id)
        self.replacer = Replacer(store, case_id)

        # Detection
        detectors = get_default_detectors(
            name_detector=name_detector,
            address_detector=address_detector,
            strict_names=strict_names,
        )
        self.coordinator = DetectionCoordinator(
            detectors,
            include_types=include_types,
            exclude_types=exclude_types,
        )

    def scan_text(self, text: str) -> List[PIIMatch]:
        """Detect PII without modifying text. For dry-run/scan mode."""
        matches = self.coordinator.detect_all(text)
        return self.allowlist.filter(matches, text)

    def anonymize_text(self, text: str, source_file: str = "") -> str:
        """Full pipeline: detect → resolve → tokenize → replace."""
        # Step 1: Detect all PII
        matches = self.coordinator.detect_all(text)

        # Step 2: Filter allowlisted values
        matches = self.allowlist.filter(matches, text)

        if not matches:
            return text

        # Step 3: For each match, resolve entity and generate/reuse token
        self._register_matches(matches, source_file)

        # Step 4: Replace using flashtext (uses all mappings in store)
        return self.replacer.anonymize_text(text)

    def deanonymize_text(self, text: str, only_types: Optional[List[str]] = None) -> str:
        """Replace tokens back to original PII values.

        Args:
            text: Text containing anonymization tokens.
            only_types: If provided, only restore tokens for these PII types.
        """
        return self.replacer.deanonymize_text(text, only_types=only_types)

    def _register_matches(self, matches: List[PIIMatch], source_file: str) -> None:
        """Register detected PII in the mapping store."""
        for match in matches:
            # Skip if already registered
            existing = self.store.get_mapping_by_raw(match.raw_value, self.case_id)
            if existing:
                continue

            # Resolve entity
            entity_id = self.resolver.resolve(
                match.pii_type, match.raw_value, source_file
            )

            # Generate token
            token = self.tokenizer.generate(match.pii_type)

            # Store mapping
            self.store.add_mapping(
                entity_id=entity_id,
                pii_type=match.pii_type,
                raw_value=match.raw_value,
                token=token,
                case_id=self.case_id,
                source_file=source_file,
            )

    def anonymize_file(
        self,
        input_path: Path,
        output_path: Path,
        adapter: Optional[FileAdapter] = None,
    ) -> dict:
        """Anonymize a single file.

        Returns a summary dict with stats.
        """
        if adapter is None:
            adapter = get_adapter(input_path)

        if adapter is None:
            return {"file": str(input_path), "status": "skipped", "reason": "unsupported format"}

        # Compute input hash
        file_hash = self._file_hash(input_path)

        # Check if already processed
        if self.store.is_processed(str(input_path), self.case_id, "anonymize"):
            return {"file": str(input_path), "status": "skipped", "reason": "already processed"}

        # Extract, anonymize, write
        output_path.parent.mkdir(parents=True, exist_ok=True)
        text = adapter.read(input_path)
        anon_text = self.anonymize_text(text, source_file=str(input_path))

        # Column-aware mode (CSV/XLSX): only process designated columns
        if (self.pii_columns or self.keep_columns) and _adapter_supports_columns(adapter):
            if hasattr(adapter, "anonymize_column_aware"):
                adapter.anonymize_column_aware(
                    input_path, output_path, self.replacer.anonymize_text,
                    pii_columns=self.pii_columns, keep_columns=self.keep_columns,
                )
            elif hasattr(adapter, "anonymize_preserving_format"):
                adapter.anonymize_preserving_format(
                    input_path, output_path, self.replacer.anonymize_text,
                    pii_columns=self.pii_columns, keep_columns=self.keep_columns,
                )
            else:
                adapter.write(output_path, anon_text)
        # Use format-preserving method if available (xlsx, docx, sqlite)
        elif hasattr(adapter, "anonymize_preserving_format"):
            adapter.anonymize_preserving_format(
                input_path, output_path, self.replacer.anonymize_text
            )
        else:
            adapter.write(output_path, anon_text)

        # Mark as processed
        self.store.mark_processed(str(input_path), self.case_id, "anonymize", file_hash)

        return {"file": str(input_path), "status": "anonymized", "output": str(output_path)}

    def deanonymize_file(
        self,
        input_path: Path,
        output_path: Path,
        adapter: Optional[FileAdapter] = None,
        only_types: Optional[List[str]] = None,
    ) -> dict:
        """De-anonymize a single file (reverse token→PII).

        Args:
            input_path: Path to the anonymized file.
            output_path: Path where the restored file will be written.
            adapter: File format adapter (auto-detected if None).
            only_types: If provided, only restore tokens for these PII types.
        """
        if adapter is None:
            adapter = get_adapter(input_path)
        if adapter is None:
            return {"file": str(input_path), "status": "skipped", "reason": "unsupported format"}

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build a bound deanonymize callable that respects only_types
        def _deanon(text: str) -> str:
            return self.deanonymize_text(text, only_types=only_types)

        # Column-aware mode (CSV/XLSX): only restore designated columns
        if (self.pii_columns or self.keep_columns) and _adapter_supports_columns(adapter):
            if hasattr(adapter, "anonymize_column_aware"):
                adapter.anonymize_column_aware(
                    input_path, output_path, _deanon,
                    pii_columns=self.pii_columns, keep_columns=self.keep_columns,
                )
            elif hasattr(adapter, "anonymize_preserving_format"):
                adapter.anonymize_preserving_format(
                    input_path, output_path, _deanon,
                    pii_columns=self.pii_columns, keep_columns=self.keep_columns,
                )
            else:
                text = adapter.read(input_path)
                adapter.write(output_path, _deanon(text))
        # Use format-preserving method if available (xlsx, docx, sqlite)
        elif hasattr(adapter, "anonymize_preserving_format"):
            adapter.anonymize_preserving_format(input_path, output_path, _deanon)
        else:
            text = adapter.read(input_path)
            restored_text = _deanon(text)
            adapter.write(output_path, restored_text)

        self.store.mark_processed(str(input_path), self.case_id, "deanonymize")
        return {"file": str(input_path), "status": "deanonymized", "output": str(output_path)}

    def anonymize_directory(
        self, input_dir: Path, output_dir: Path, recursive: bool = True
    ) -> List[dict]:
        """Anonymize all supported files in a directory.

        Uses a two-pass approach:
        1. Scan all files to build complete PII mapping store
        2. Replace using the full mapping store
        This ensures cross-file consistency (a password found in file C
        will also be replaced in file A, regardless of processing order).
        """
        pattern = "**/*" if recursive else "*"
        file_pairs = []

        for input_path in sorted(input_dir.glob(pattern)):
            if input_path.is_dir():
                continue
            rel = input_path.relative_to(input_dir)
            output_path = output_dir / rel
            file_pairs.append((input_path, output_path))

        # Pass 1: Scan all files and register all PII in the mapping store
        for input_path, _ in file_pairs:
            adapter = get_adapter(input_path)
            if adapter is None:
                continue
            text = adapter.read(input_path)
            matches = self.coordinator.detect_all(text)
            matches = self.allowlist.filter(matches, text)
            self._register_matches(matches, str(input_path))

        # Pass 2: Replace using the complete mapping store
        results = []
        for input_path, output_path in file_pairs:
            adapter = get_adapter(input_path)
            if adapter is None:
                results.append({"file": str(input_path), "status": "skipped", "reason": "unsupported format"})
                continue

            if self.store.is_processed(str(input_path), self.case_id, "anonymize"):
                results.append({"file": str(input_path), "status": "skipped", "reason": "already processed"})
                continue

            file_hash = self._file_hash(input_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            text = adapter.read(input_path)
            anon_text = self.replacer.anonymize_text(text)
            adapter.write(output_path, anon_text)
            self.store.mark_processed(str(input_path), self.case_id, "anonymize", file_hash)
            results.append({"file": str(input_path), "status": "anonymized", "output": str(output_path)})

        return results

    def deanonymize_directory(
        self,
        input_dir: Path,
        output_dir: Path,
        recursive: bool = True,
        only_types: Optional[List[str]] = None,
    ) -> List[dict]:
        """De-anonymize all files in a directory.

        Args:
            input_dir: Directory containing anonymized files.
            output_dir: Directory where restored files will be written.
            recursive: Whether to recurse into subdirectories.
            only_types: If provided, only restore tokens for these PII types.
        """
        results = []
        pattern = "**/*" if recursive else "*"

        for input_path in sorted(input_dir.glob(pattern)):
            if input_path.is_dir():
                continue
            rel = input_path.relative_to(input_dir)
            output_path = output_dir / rel
            result = self.deanonymize_file(input_path, output_path, only_types=only_types)
            results.append(result)

        return results

    def verify(self, original_path: Path, anonymized_path: Path) -> List[str]:
        """Check if any raw PII values from the mapping store appear in the anonymized file."""
        adapter = get_adapter(anonymized_path)
        if adapter is None:
            return [f"Cannot verify: unsupported format {anonymized_path.suffix}"]

        anon_text = adapter.read(anonymized_path)
        mappings = self.store.get_all_mappings(self.case_id)
        leaks = []

        for m in mappings:
            raw = m["raw_value"]
            if len(raw) >= 4 and raw in anon_text:
                leaks.append(f"LEAK: '{raw}' (type={m['pii_type']}, token={m['token']}) found in {anonymized_path}")

        return leaks

    @staticmethod
    def _file_hash(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


# ---------- module-level helpers ----------

def _adapter_supports_columns(adapter) -> bool:
    """Return True if the adapter declares column-aware support."""
    return callable(getattr(adapter, "supports_columns", None)) and adapter.supports_columns()
