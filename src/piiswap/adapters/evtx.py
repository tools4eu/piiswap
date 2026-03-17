"""Windows Event Log (.evtx) adapter using python-evtx."""

from pathlib import Path

from piiswap.adapters.base import FileAdapter, register_adapter


@register_adapter
class EvtxAdapter(FileAdapter):
    """Read Windows Event Log files (.evtx).

    Extracts event XML and converts to text for anonymization.
    Output is written as XML/text since .evtx is a read-only binary format.
    """

    supported_extensions = (".evtx",)

    def read(self, path: Path) -> str:
        import Evtx.Evtx as evtx

        parts = []
        with evtx.Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    parts.append(xml_str)
                except Exception:
                    # Some records may be corrupt
                    continue

        return "\n".join(parts)

    def write(self, path: Path, content: str) -> None:
        """Write anonymized event data as XML text.

        EVTX is a binary format — anonymized output is saved as .xml.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        xml_path = path.with_suffix(".xml")
        xml_path.write_text(content, encoding="utf-8")
