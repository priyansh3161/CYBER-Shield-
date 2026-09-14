"""
crypto_feature_extractor.py
Stage 6: Cryptographic Feature Extraction

Combines the TLS handshake parser output with the `cryptography` library's
X.509 parser to produce a structured CryptoFeatures object per stream:
TLS version, cipher suite, key exchange type, certificate details
(issuer, subject, validity, key size, signature algorithm), and signature
algorithm.
"""

from typing import Optional, List, Dict, Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from models import TCPStream, CryptoFeatures
from tls_handshake_parser import TLSHandshakeParser, HANDSHAKE_TYPE


class CryptoFeatureExtractor:
    @staticmethod
    def extract(stream: TCPStream) -> CryptoFeatures:
        features = CryptoFeatures(stream_id=stream.stream_id)

        combined_records = list(TLSHandshakeParser.find_records(stream.raw_client_bytes)) + \
                            list(TLSHandshakeParser.find_records(stream.raw_server_bytes))

        for content_type, version, body in combined_records:
            if content_type != 22:  # 22 = Handshake
                continue
            for msg_type, msg_body in TLSHandshakeParser.parse_handshake_messages(body):
                if msg_type == 1:  # ClientHello
                    ch = TLSHandshakeParser.parse_client_hello(msg_body)
                    features.sni = ch.get("sni") or features.sni
                elif msg_type == 2:  # ServerHello
                    sh = TLSHandshakeParser.parse_server_hello(msg_body)
                    features.tls_version = sh.get("tls_version")
                    features.cipher_suite = sh.get("cipher_suite")
                    features.key_exchange = CryptoFeatureExtractor._infer_key_exchange(
                        sh.get("cipher_suite")
                    )
                elif msg_type == 11:  # Certificate
                    der_list = TLSHandshakeParser.parse_certificate_message(msg_body)
                    for der in der_list:
                        cert_info = CryptoFeatureExtractor._parse_x509(der)
                        if cert_info:
                            features.certificates.append(cert_info)
                            if not features.signature_algorithm:
                                features.signature_algorithm = cert_info.get("signature_algorithm")

        return features

    @staticmethod
    def _infer_key_exchange(cipher_suite: Optional[str]) -> Optional[str]:
        if not cipher_suite:
            return None
        cs = cipher_suite.upper()
        if "ECDHE" in cs:
            return "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)"
        if cs.startswith("TLS_AES") or cs.startswith("TLS_CHACHA20"):
            return "TLS 1.3 (key_share / (EC)DHE)"
        if "DHE" in cs:
            return "DHE (Diffie-Hellman Ephemeral)"
        if "RSA" in cs:
            return "RSA Key Transport (no forward secrecy)"
        return "Unknown"

    @staticmethod
    def _parse_x509(der_bytes: bytes) -> Optional[Dict[str, Any]]:
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception:
            return None

        pub_key = cert.public_key()
        key_type, key_size = "Unknown", None
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type, key_size = "RSA", pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type, key_size = f"EC ({pub_key.curve.name})", pub_key.curve.key_size

        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            # Older cryptography versions
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "public_key_type": key_type,
            "public_key_size": key_size,
            "signature_algorithm": cert.signature_algorithm_oid._name
                if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid),
            "is_self_signed": cert.subject == cert.issuer,
        }
