"""
models.py
Shared dataclasses used across the PCAP Forensic Analysis Pipeline.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class TCPStream:
    """Represents one reconstructed TCP stream (a single email session)."""
    stream_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Optional[str] = None          # SMTP / IMAP / POP3
    raw_client_bytes: bytes = b""
    raw_server_bytes: bytes = b""
    starttls_seen: bool = False
    starttls_upgrade_ok: bool = False
    tls_client_hello: Optional[bytes] = None
    tls_server_hello: Optional[bytes] = None
    tls_certificates: Optional[bytes] = None
    packet_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0


@dataclass
class CryptoFeatures:
    """Cryptographic features extracted from a single stream's TLS handshake."""
    stream_id: str
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    certificates: List[Dict[str, Any]] = field(default_factory=list)
    signature_algorithm: Optional[str] = None
    sni: Optional[str] = None


@dataclass
class SecurityFinding:
    stream_id: str
    severity: str            # "critical" | "high" | "medium" | "low" | "info"
    category: str            # e.g. "Deprecated TLS", "Weak Cipher", "Expired Cert"
    description: str
    recommendation: str


@dataclass
class StreamVerdict:
    """Final per-stream verdict combining static rules + AI/ML scoring."""
    stream_id: str
    src_ip: str
    dst_ip: str
    protocol: Optional[str]
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    risk_score: int                 # 0-100
    risk_classification: str        # "Critical" | "High" | "Medium" | "Low" | "Safe"
    anomaly: bool
    findings: List[SecurityFinding] = field(default_factory=list)
    ml_predictions: Dict[str, Any] = field(default_factory=dict)  # populated only if a trained model is loaded
