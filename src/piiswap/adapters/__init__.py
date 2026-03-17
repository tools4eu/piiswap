# Import adapters so they get registered via @register_adapter
from piiswap.adapters.plaintext import PlainTextAdapter

# CsvAdapter has no external dependencies — always available
try:
    from piiswap.adapters.csv_adapter import CsvAdapter
except ImportError:
    CsvAdapter = None

# Optional format adapters — only register if dependencies are installed
try:
    from piiswap.adapters.docx import DocxAdapter
except ImportError:
    DocxAdapter = None

try:
    from piiswap.adapters.pdf import PdfAdapter
except ImportError:
    PdfAdapter = None

try:
    from piiswap.adapters.sqlite_adapter import SqliteAdapter
except ImportError:
    SqliteAdapter = None

try:
    from piiswap.adapters.evtx import EvtxAdapter
except ImportError:
    EvtxAdapter = None

try:
    from piiswap.adapters.pcap import PcapAdapter
except ImportError:
    PcapAdapter = None

try:
    from piiswap.adapters.xlsx import XlsxAdapter
except ImportError:
    XlsxAdapter = None

__all__ = [
    "PlainTextAdapter",
    "CsvAdapter",
    "DocxAdapter",
    "PdfAdapter",
    "SqliteAdapter",
    "EvtxAdapter",
    "PcapAdapter",
    "XlsxAdapter",
]
