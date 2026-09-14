"""
tls_handshake_parser.py
Stage 5: TLS Handshake Parsing

Parses raw TLS record bytes to locate the ClientHello, ServerHello and
Certificate handshake messages. Uses scapy's TLS layer if scapy-ssl_tls /
scapy.layers.tls is available; otherwise falls back to a minimal manual
byte-level parser sufficient to pull out version, cipher suite and
certificate DER blobs (adequate for forensic triage, not a full TLS stack).
"""

import struct
from typing import Optional, Dict, Any

TLS_VERSION_MAP = {
    (3, 0): "SSL 3.0",
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2",
    (3, 4): "TLS 1.3",
}

# Minimal cipher suite table covering common values seen in the wild
CIPHER_SUITE_MAP = {
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",   # weak
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",         # weak
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",         # weak
}

HANDSHAKE_TYPE = {1: "ClientHello", 2: "ServerHello", 11: "Certificate"}


class TLSHandshakeParser:
    """
    Walks a byte stream looking for TLS record headers (0x16 0x03 xx) and
    parses the handshake message(s) inside each record.
    """

    @staticmethod
    def find_records(data: bytes):
        """Yields (record_type, version_tuple, record_body) for each TLS
        record found in the byte stream."""
        i = 0
        n = len(data)
        while i + 5 <= n:
            content_type = data[i]
            if content_type not in (20, 21, 22, 23):  # not a valid TLS record type
                i += 1
                continue
            major, minor = data[i + 1], data[i + 2]
            length = struct.unpack(">H", data[i + 3:i + 5])[0]
            body_start = i + 5
            body_end = body_start + length
            if body_end > n:
                break
            yield content_type, (major, minor), data[body_start:body_end]
            i = body_end

    @staticmethod
    def parse_handshake_messages(record_body: bytes):
        """A handshake record can contain one or more handshake messages,
        each framed as: msg_type(1) + length(3) + body."""
        i = 0
        n = len(record_body)
        while i + 4 <= n:
            msg_type = record_body[i]
            length = int.from_bytes(record_body[i + 1:i + 4], "big")
            body_start = i + 4
            body_end = body_start + length
            if body_end > n:
                break
            yield msg_type, record_body[body_start:body_end]
            i = body_end

    @classmethod
    def parse_client_hello(cls, body: bytes) -> Dict[str, Any]:
        result = {"tls_version": None, "sni": None}
        try:
            major, minor = body[0], body[1]
            result["tls_version"] = TLS_VERSION_MAP.get((major, minor), f"Unknown(0x{major:02x}{minor:02x})")

            pos = 2 + 32  # skip client_random
            session_id_len = body[pos]
            pos += 1 + session_id_len

            cipher_suites_len = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2 + cipher_suites_len

            compression_len = body[pos]
            pos += 1 + compression_len

            if pos + 2 <= len(body):
                ext_total_len = struct.unpack(">H", body[pos:pos + 2])[0]
                pos += 2
                ext_end = pos + ext_total_len
                while pos + 4 <= ext_end and pos + 4 <= len(body):
                    ext_type = struct.unpack(">H", body[pos:pos + 2])[0]
                    ext_len = struct.unpack(">H", body[pos + 2:pos + 4])[0]
                    ext_body = body[pos + 4:pos + 4 + ext_len]
                    if ext_type == 0x0000:  # server_name extension
                        result["sni"] = cls._parse_sni(ext_body)
                    pos += 4 + ext_len
        except (IndexError, struct.error):
            pass
        return result

    @staticmethod
    def _parse_sni(ext_body: bytes) -> Optional[str]:
        try:
            # server_name_list length (2) -> entry type (1) -> name length (2) -> name
            name_len = struct.unpack(">H", ext_body[3:5])[0]
            return ext_body[5:5 + name_len].decode("ascii", errors="ignore")
        except (IndexError, struct.error):
            return None

    @classmethod
    def parse_server_hello(cls, body: bytes) -> Dict[str, Any]:
        result = {"tls_version": None, "cipher_suite": None}
        try:
            major, minor = body[0], body[1]
            result["tls_version"] = TLS_VERSION_MAP.get((major, minor), f"Unknown(0x{major:02x}{minor:02x})")

            pos = 2 + 32
            session_id_len = body[pos]
            pos += 1 + session_id_len

            cipher_id = struct.unpack(">H", body[pos:pos + 2])[0]
            result["cipher_suite"] = CIPHER_SUITE_MAP.get(cipher_id, f"Unknown(0x{cipher_id:04x})")
        except (IndexError, struct.error):
            pass
        return result

    @staticmethod
    def parse_certificate_message(body: bytes):
        """Extracts the raw DER bytes of each certificate in a TLS 1.2-style
        Certificate handshake message. Returns a list of DER blobs."""
        certs = []
        try:
            pos = 3  # skip certificate_list total length (3 bytes)
            total_len = int.from_bytes(body[0:3], "big")
            end = 3 + total_len
            while pos + 3 <= end and pos + 3 <= len(body):
                cert_len = int.from_bytes(body[pos:pos + 3], "big")
                pos += 3
                cert_der = body[pos:pos + cert_len]
                certs.append(cert_der)
                pos += cert_len
        except (IndexError, ValueError):
            pass
        return certs
