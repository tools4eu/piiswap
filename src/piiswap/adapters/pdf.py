"""PDF adapter using pdfplumber (read-only, outputs as .txt)."""

from pathlib import Path

from piiswap.adapters.base import FileAdapter, register_adapter


@register_adapter
class PdfAdapter(FileAdapter):
    """Read text from PDF files.

    Note: PDF is read-only. Anonymized output is written as plain text (.txt)
    because modifying PDF content while preserving layout is not reliably possible.
    """

    supported_extensions = (".pdf",)

    def read(self, path: Path) -> str:
        import pdfplumber

        parts = []
        with pdfplumber.open(str(path)) as pdf:
            for i, page in enumerate(pdf.pages, 1):
                text = page.extract_text()
                if text:
                    parts.append(f"--- Page {i} ---")
                    parts.append(text)

                # Extract tables separately for better structure
                tables = page.extract_tables()
                for table in tables:
                    for row in table:
                        cells = [str(cell) if cell else "" for cell in row]
                        parts.append("\t".join(cells))

        return "\n".join(parts)

    def write(self, path: Path, content: str) -> None:
        """Write anonymized content as plain text.

        PDF write-back is not supported — output goes to .txt with same stem.
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        # Change extension to .txt since we can't write PDF
        txt_path = path.with_suffix(".txt")
        txt_path.write_text(content, encoding="utf-8")
