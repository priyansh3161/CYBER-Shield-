"""
protocol_identifier.py
Stage 2: Protocol Identification (SMTP / IMAP / POP3)

Identifies the application-layer email protocol of a TCP flow using a
combination of well-known ports and banner/command signatures found in
the first few payload bytes.
"""

from typing import Optional, List

WELL_KNOWN_PORTS = {
    25: "SMTP", 587: "SMTP", 465: "SMTP-SSL",
    143: "IMAP", 993: "IMAP-SSL",
    110: "POP3", 995: "POP3-SSL",
}

SMTP_SIGNATURES = [b"220 ", b"EHLO", b"HELO", b"MAIL FROM", b"RCPT TO", b"DATA"]
IMAP_SIGNATURES = [b"* OK", b"a1 LOGIN", b"a1 SELECT", b"CAPABILITY"]
POP3_SIGNATURES = [b"+OK", b"USER ", b"PASS ", b"RETR "]


class ProtocolIdentifier:
    @staticmethod
    def identify(ports: List[int], payload_sample: bytes) -> Optional[str]:
        # 1. Fast path: well-known port match
        for p in ports:
            if p in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[p]

        # 2. Fallback: payload signature sniffing (handles non-standard ports)
        sample = payload_sample or b""
        if any(sig in sample for sig in SMTP_SIGNATURES):
            return "SMTP"
        if any(sig in sample for sig in IMAP_SIGNATURES):
            return "IMAP"
        if any(sig in sample for sig in POP3_SIGNATURES):
            return "POP3"

        return None
