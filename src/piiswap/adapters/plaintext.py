"""Plain text file adapter for .txt, .log, .md, .conf, .cfg, .ini, .sql, .php, .xml, etc."""

from pathlib import Path

from piiswap.adapters.base import FileAdapter, register_adapter


@register_adapter
class PlainTextAdapter(FileAdapter):
    """Handles any text-based file format."""

    supported_extensions = (
        ".txt", ".log", ".md", ".conf", ".cfg", ".ini",
        ".sql", ".php", ".xml", ".html", ".htm",
        ".yaml", ".yml", ".json",
        ".sh", ".bat", ".ps1", ".py", ".js",
        ".eml", ".env", ".properties",
    )

    def read(self, path: Path) -> str:
        # Try UTF-8 first, fall back to latin-1 (never fails)
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1")

    def write(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
