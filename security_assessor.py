"""
security_assessor.py
Stage 7: Security Assessment (Static Rules)

Applies deterministic, well-known cryptographic hygiene rules:
  - Deprecated TLS versions (SSLv3, TLS 1.0, TLS 1.1)
  - Weak cipher suites (RC4, 3DES, NULL, export-grade, non-PFS RSA)
  - Insecure configurations (missing STARTTLS upgrade, plaintext creds)
  - Certificate validation (self-signed, weak key size)
  - Expiration check
  - Forward secrecy check
"""

from datetime import datetime, timezone
from typing import List

from models import TCPStream, CryptoFeatures, SecurityFinding

DEPRECATED_TLS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
WEAK_CIPHER_KEYWORDS = ["RC4", "3DES", "NULL", "EXPORT", "MD5", "DES"]
MIN_RSA_KEY_SIZE = 2048
MIN_EC_KEY_SIZE = 224


class SecurityAssessor:
    @staticmethod
    def assess(stream: TCPStream, features: CryptoFeatures) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        sid = stream.stream_id

        # --- Deprecated TLS version ---
        if features.tls_version in DEPRECATED_TLS:
            findings.append(SecurityFinding(
                stream_id=sid, severity="high", category="Deprecated TLS Version",
                description=f"Session negotiated {features.tls_version}, which is deprecated and vulnerable to known attacks (e.g. POODLE, BEAST).",
                recommendation="Disable SSLv3/TLS1.0/TLS1.1 on the mail server; enforce TLS 1.2 or higher.",
            ))

        # --- Weak cipher suite ---
        if features.cipher_suite and any(k in features.cipher_suite.upper() for k in WEAK_CIPHER_KEYWORDS):
            findings.append(SecurityFinding(
                stream_id=sid, severity="critical", category="Weak Cipher Suite",
                description=f"Negotiated cipher suite {features.cipher_suite} uses a broken/weak primitive.",
                recommendation="Remove RC4/3DES/NULL/EXPORT/MD5-based suites from the server's cipher list; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).",
            ))

        # --- Forward secrecy check ---
        if features.key_exchange and "no forward secrecy" in features.key_exchange.lower():
            findings.append(SecurityFinding(
                stream_id=sid, severity="medium", category="No Forward Secrecy",
                description="Key exchange uses static RSA key transport; a compromised private key can decrypt all past recorded traffic.",
                recommendation="Reconfigure server to prioritize ECDHE/DHE cipher suites for forward secrecy.",
            ))

        # --- Missing STARTTLS / plaintext session ---
        if stream.protocol in ("SMTP", "IMAP", "POP3") and not stream.starttls_seen and not features.tls_version:
            findings.append(SecurityFinding(
                stream_id=sid, severity="high", category="Unencrypted Session",
                description=f"{stream.protocol} session completed with no STARTTLS/TLS observed — credentials and message content likely sent in plaintext.",
                recommendation="Enforce mandatory STARTTLS (reject plaintext AUTH) or require implicit TLS ports (465/993/995).",
            ))
        elif stream.starttls_seen and not stream.starttls_upgrade_ok:
            findings.append(SecurityFinding(
                stream_id=sid, severity="critical", category="STARTTLS Downgrade / Stripping",
                description="Client requested STARTTLS but no successful upgrade to a TLS record layer was observed afterward — possible STARTTLS-stripping attack.",
                recommendation="Investigate for a man-in-the-middle stripping the STARTTLS response; enable MTA-STS / implicit TLS to prevent downgrade.",
            ))

        # --- Certificate checks ---
        now = datetime.now(timezone.utc)
        for cert in features.certificates:
            if cert.get("is_self_signed"):
                findings.append(SecurityFinding(
                    stream_id=sid, severity="medium", category="Self-Signed Certificate",
                    description=f"Certificate for subject '{cert['subject']}' is self-signed and not verifiable by a public CA.",
                    recommendation="Replace with a certificate issued by a trusted CA, or pin the cert explicitly if this is intentional (internal infra).",
                ))

            try:
                not_after = datetime.fromisoformat(cert["not_after"])
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                if not_after < now:
                    findings.append(SecurityFinding(
                        stream_id=sid, severity="critical", category="Expired Certificate",
                        description=f"Certificate for '{cert['subject']}' expired on {cert['not_after']}.",
                        recommendation="Renew the certificate immediately; expired certs break trust and may indicate poor cert lifecycle management.",
                    ))
                elif (not_after - now).days < 15:
                    findings.append(SecurityFinding(
                        stream_id=sid, severity="low", category="Certificate Expiring Soon",
                        description=f"Certificate for '{cert['subject']}' expires in under 15 days ({cert['not_after']}).",
                        recommendation="Schedule certificate renewal to avoid an unplanned outage or fallback to plaintext.",
                    ))
            except (KeyError, ValueError):
                pass

            key_type = cert.get("public_key_type", "")
            key_size = cert.get("public_key_size") or 0
            if key_type == "RSA" and key_size < MIN_RSA_KEY_SIZE:
                findings.append(SecurityFinding(
                    stream_id=sid, severity="high", category="Weak Key Size",
                    description=f"RSA public key size is {key_size} bits (< {MIN_RSA_KEY_SIZE}).",
                    recommendation="Reissue the certificate with an RSA key of at least 2048 bits, or migrate to ECDSA.",
                ))
            elif key_type.startswith("EC") and key_size and key_size < MIN_EC_KEY_SIZE:
                findings.append(SecurityFinding(
                    stream_id=sid, severity="high", category="Weak Key Size",
                    description=f"EC public key size is {key_size} bits (< {MIN_EC_KEY_SIZE}).",
                    recommendation="Reissue the certificate on a stronger curve (P-256 or higher).",
                ))

            sig_alg = (cert.get("signature_algorithm") or "").lower()
            if "md5" in sig_alg or "sha1" in sig_alg:
                findings.append(SecurityFinding(
                    stream_id=sid, severity="high", category="Weak Signature Algorithm",
                    description=f"Certificate signed using {cert.get('signature_algorithm')}, which is cryptographically broken/deprecated.",
                    recommendation="Reissue the certificate with SHA-256 or stronger signature algorithm.",
                ))

        return findings
