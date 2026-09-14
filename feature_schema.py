"""
feature_schema.py
Single source of truth for the numeric feature vector used by BOTH:
  - live inference (ai_ml_analyzer.py -> IsolationForest / trained classifiers)
  - offline training (train_model.py)

Keeping this in one place guarantees training-time and inference-time
features never drift apart (a very common source of silent ML bugs).
"""

from typing import List
from models import TCPStream, CryptoFeatures

FEATURE_NAMES = [
    "packet_count",
    "duration_seconds",
    "tls_version_rank",     # -1 = no TLS seen, 0=SSLv3 ... 4=TLS1.3
    "public_key_size",
    "starttls_seen",         # 0/1
    "starttls_upgrade_ok",   # 0/1
    "cert_validity_days",    # total validity window of first cert, 0 if none
    "num_certificates",
]

TLS_VERSION_RANK = {
    "SSL 3.0": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4,
}


def vectorize(stream: TCPStream, features: CryptoFeatures) -> List[float]:
    duration = max(stream.end_time - stream.start_time, 0.0)
    tls_rank = TLS_VERSION_RANK.get(features.tls_version, -1)

    key_size = 0
    cert_validity_days = 0
    if features.certificates:
        cert = features.certificates[0]
        key_size = cert.get("public_key_size") or 0
        try:
            from datetime import datetime
            nb = datetime.fromisoformat(cert["not_before"])
            na = datetime.fromisoformat(cert["not_after"])
            cert_validity_days = max((na - nb).days, 0)
        except (KeyError, ValueError):
            pass

    return [
        float(stream.packet_count),
        duration,
        float(tls_rank),
        float(key_size),
        1.0 if stream.starttls_seen else 0.0,
        1.0 if stream.starttls_upgrade_ok else 0.0,
        float(cert_validity_days),
        float(len(features.certificates)),
    ]
