"""Base class for all PII detectors."""

from dataclasses import dataclass
from typing import List


@dataclass
class PIIMatch:
    """A detected PII occurrence in text."""
    start: int
    end: int
    raw_value: str
    pii_type: str
    confidence: float = 1.0

    @property
    def length(self) -> int:
        return self.end - self.start


class BaseDetector:
    """Abstract base for PII detectors."""

    pii_type: str = "unknown"

    def detect(self, text: str) -> List[PIIMatch]:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.pii_type}>"
