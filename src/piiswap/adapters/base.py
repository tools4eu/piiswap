"""Base file adapter and adapter registry."""

from pathlib import Path
from typing import Optional


class FileAdapter:
    """Base class for file format adapters."""

    supported_extensions: tuple = ()

    def read(self, path: Path) -> str:
        """Read file and return text content."""
        raise NotImplementedError

    def write(self, path: Path, content: str) -> None:
        """Write text content to file."""
        raise NotImplementedError

    @classmethod
    def supports(cls, path: Path) -> bool:
        return path.suffix.lower() in cls.supported_extensions


# Registry of all available adapters
_ADAPTERS: list = []


def register_adapter(adapter_class):
    """Register an adapter class."""
    _ADAPTERS.append(adapter_class)
    return adapter_class


def get_adapter(path: Path) -> Optional[FileAdapter]:
    """Find the right adapter for a file path."""
    for adapter_cls in _ADAPTERS:
        if adapter_cls.supports(path):
            return adapter_cls()
    return None
