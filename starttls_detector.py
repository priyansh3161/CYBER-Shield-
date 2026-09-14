"""
starttls_detector.py
Stage 4: STARTTLS Detection & Transitions

Detects whether a plaintext email session issued a STARTTLS-style command
and whether the server accepted the upgrade, marking the byte offset in
the stream where plaintext ends and the TLS record layer begins.
"""

import re
from typing import Optional, Tuple

from models import TCPStream

STARTTLS_COMMANDS = {
    "SMTP": re.compile(rb"STARTTLS\r?\n", re.IGNORECASE),
    "IMAP": re.compile(rb"STARTTLS\r?\n", re.IGNORECASE),
    "POP3": re.compile(rb"STLS\r?\n", re.IGNORECASE),
}

# Server acknowledgement patterns that indicate the upgrade was accepted
STARTTLS_ACK = {
    "SMTP": re.compile(rb"220 .*(TLS|Ready)", re.IGNORECASE),
    "IMAP": re.compile(rb"(a\d+ OK|OK Begin TLS)", re.IGNORECASE),
    "POP3": re.compile(rb"\+OK", re.IGNORECASE),
}

TLS_RECORD_HEADER = b"\x16\x03"  # Handshake record, TLS 1.x


class STARTTLSDetector:
    @staticmethod
    def detect(stream: TCPStream) -> Tuple[bool, bool, Optional[int]]:
        """
        Returns:
            starttls_seen: client issued a STARTTLS/STLS command
            upgrade_ok: server acknowledged and a TLS record header follows
            tls_offset: byte index in raw_server_bytes where TLS begins
        """
        proto = stream.protocol
        if proto not in STARTTLS_COMMANDS:
            return False, False, None

        cmd_match = STARTTLS_COMMANDS[proto].search(stream.raw_client_bytes)
        if not cmd_match:
            # Could still be implicit TLS (SMTPS/IMAPS/POP3S on dedicated port)
            return STARTTLSDetector._check_implicit_tls(stream)

        ack_match = STARTTLS_ACK[proto].search(stream.raw_server_bytes)
        if not ack_match:
            return True, False, None

        # Look for the TLS record header immediately after the ack in the
        # server stream — that marks where plaintext ends.
        search_from = ack_match.end()
        tls_idx = stream.raw_server_bytes.find(TLS_RECORD_HEADER, search_from)
        if tls_idx == -1:
            tls_idx = stream.raw_client_bytes.find(TLS_RECORD_HEADER)

        return True, tls_idx != -1, (tls_idx if tls_idx != -1 else None)

    @staticmethod
    def _check_implicit_tls(stream: TCPStream) -> Tuple[bool, bool, Optional[int]]:
        """Handles SMTPS/IMAPS/POP3S: TLS starts at byte 0, no STARTTLS cmd."""
        if stream.raw_server_bytes[:2] == TLS_RECORD_HEADER or \
           stream.raw_client_bytes[:2] == TLS_RECORD_HEADER:
            return False, True, 0
        return False, False, None
