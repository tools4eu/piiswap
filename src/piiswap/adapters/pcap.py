"""PCAP/PCAPNG adapter using scapy — extracts text payloads for anonymization."""

from pathlib import Path

from piiswap.adapters.base import FileAdapter, register_adapter


@register_adapter
class PcapAdapter(FileAdapter):
    """Read network capture files (.pcap, .pcapng).

    Extracts packet summaries and text-based payloads (HTTP, DNS, SMTP, etc.)
    for PII detection. Output is written as plain text since PCAP is read-only.
    """

    supported_extensions = (".pcap", ".pcapng", ".cap")

    def read(self, path: Path) -> str:
        from scapy.all import rdpcap, Raw, DNS, IP, IPv6, TCP, UDP

        parts = []
        packets = rdpcap(str(path))

        for i, pkt in enumerate(packets, 1):
            lines = [f"--- Packet {i} ---"]

            # IP layer
            if pkt.haslayer(IP):
                ip = pkt[IP]
                lines.append(f"IP: {ip.src} -> {ip.dst}")
            elif pkt.haslayer(IPv6):
                ip6 = pkt[IPv6]
                lines.append(f"IPv6: {ip6.src} -> {ip6.dst}")

            # Transport
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                lines.append(f"TCP: {tcp.sport} -> {tcp.dport}")
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                lines.append(f"UDP: {udp.sport} -> {udp.dport}")

            # DNS
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                try:
                    if dns.qd:
                        lines.append(f"DNS Query: {dns.qd.qname.decode(errors='replace')}")
                except Exception:
                    pass

            # Raw payload — try to decode as text
            if pkt.haslayer(Raw):
                raw_data = pkt[Raw].load
                try:
                    text = raw_data.decode("utf-8", errors="replace")
                    # Only include if it looks like text (>70% printable)
                    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
                    if len(text) > 0 and printable / len(text) > 0.7:
                        lines.append(f"Payload:\n{text}")
                except Exception:
                    pass

            if len(lines) > 1:  # More than just the header
                parts.append("\n".join(lines))

        return "\n\n".join(parts)

    def write(self, path: Path, content: str) -> None:
        """Write anonymized packet data as plain text.

        PCAP is a binary format — anonymized output is saved as .txt.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        txt_path = path.with_suffix(".txt")
        txt_path.write_text(content, encoding="utf-8")
