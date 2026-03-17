"""PII detection coordinator: runs all detectors and deduplicates results."""

from typing import List, Optional

from piiswap.detectors.base import BaseDetector, PIIMatch
from piiswap.detectors.email import EmailDetector
from piiswap.detectors.phone import PhoneDetector
from piiswap.detectors.iban import IBANDetector
from piiswap.detectors.apikey import APIKeyDetector
from piiswap.detectors.credential import CredentialDetector
from piiswap.detectors.filepath import FilePathUserDetector
from piiswap.detectors.hostname import HostnamePIIDetector
from piiswap.detectors.username import UsernameDetector
from piiswap.detectors.social import SocialHandleDetector
from piiswap.detectors.fieldlabel import FieldLabelDetector


def get_default_detectors(
    name_detector=None,
    address_detector=None,
    strict_names: bool = False,
) -> List[BaseDetector]:
    """Create the default detector stack.

    Regex detectors are always included.
    Name/address detectors are optional (require wordlist data).
    """
    detectors: List[BaseDetector] = [
        # Regex detectors (high precision) — order matters for priority
        EmailDetector(),
        PhoneDetector(),
        IBANDetector(),
        APIKeyDetector(),
        CredentialDetector(),
        FilePathUserDetector(),
        HostnamePIIDetector(),
        UsernameDetector(),
        SocialHandleDetector(),
        FieldLabelDetector(),
    ]

    # Wordlist detectors (if available)
    if name_detector:
        detectors.append(name_detector)
    if address_detector:
        detectors.append(address_detector)

    return detectors


class DetectionCoordinator:
    """Runs all detectors and deduplicates overlapping matches."""

    def __init__(
        self,
        detectors: List[BaseDetector],
        include_types: Optional[List[str]] = None,
        exclude_types: Optional[List[str]] = None,
    ):
        self.detectors = detectors
        # Normalise to sets for O(1) lookup; None means "no filter active"
        self.include_types = set(include_types) if include_types else None
        self.exclude_types = set(exclude_types) if exclude_types else None

    def detect_all(self, text: str) -> List[PIIMatch]:
        """Run all detectors and return deduplicated, non-overlapping matches.

        When matches overlap, the longer match wins.
        When same length, higher confidence wins.

        Type filtering (include_types / exclude_types) is applied at two levels:
        - Detector level: skip detectors whose pii_type is fully excluded/not included.
        - Match level: post-filter any remaining matches (catches detectors that
          emit multiple pii_types from a single detector).
        """
        all_matches: List[PIIMatch] = []
        for detector in self.detectors:
            # Fast path: skip the detector entirely when its declared type is
            # outside the requested filter set.
            detector_type = detector.pii_type
            if self.include_types is not None and detector_type not in self.include_types:
                continue
            if self.exclude_types is not None and detector_type in self.exclude_types:
                continue

            matches = detector.detect(text)

            # Post-filter individual matches (handles detectors that produce
            # matches of a different pii_type than their class attribute).
            if self.include_types is not None:
                matches = [m for m in matches if m.pii_type in self.include_types]
            if self.exclude_types is not None:
                matches = [m for m in matches if m.pii_type not in self.exclude_types]

            all_matches.extend(matches)

        return self._deduplicate(all_matches)

    @staticmethod
    def _deduplicate(matches: List[PIIMatch]) -> List[PIIMatch]:
        """Remove overlapping matches, keeping the best one."""
        if not matches:
            return []

        # Sort by: longer match first, then higher confidence, then earlier start
        matches.sort(key=lambda m: (-m.length, -m.confidence, m.start))

        kept: List[PIIMatch] = []
        occupied = set()

        for match in matches:
            # Check if any position in this match is already occupied
            span = set(range(match.start, match.end))
            if span & occupied:
                continue
            kept.append(match)
            occupied.update(span)

        # Return sorted by position
        kept.sort(key=lambda m: m.start)
        return kept
