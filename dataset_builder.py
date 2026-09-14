"""
dataset_builder.py
Builds a labeled training CSV from your own labeled PCAP captures, running
each one through the SAME Stage 1-6 pipeline used at inference time. This
guarantees the training data and live data share an identical feature
schema (see feature_schema.py) — the single most common way ML pipelines
silently break.

Expected folder layout:

    labeled_captures/
        normal/
            capture1.pcap
            capture2.pcap
        malicious/
            phishing_session1.pcap
            c2_beacon.pcap

Optionally, a risk-category CSV (filename,risk_category) can be supplied
for the multiclass target — if omitted, risk_category is derived
automatically from the static rule engine's own classification (Stage 7+8
rule score), which is a reasonable bootstrap label when you don't yet have
analyst-reviewed ground truth.

Usage:
    python dataset_builder.py labeled_captures/ --out training_data.csv
    python dataset_builder.py labeled_captures/ --out training_data.csv --risk-labels risk_labels.csv
"""

import argparse
import csv
import os
from typing import Dict, Optional

from traffic_dissection import TrafficDissector
from stream_reconstructor import StreamReconstructor
from starttls_detector import STARTTLSDetector
from crypto_feature_extractor import CryptoFeatureExtractor
from security_assessor import SecurityAssessor
from feature_schema import vectorize, FEATURE_NAMES

RISK_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}


def _bootstrap_risk_category(findings) -> str:
    score = min(sum(RISK_WEIGHTS.get(f.severity, 0) for f in findings), 100)
    if score >= 70:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    if score > 0:
        return "Low"
    return "Safe"


def process_pcap(pcap_path: str):
    """Runs stages 1-7 on one pcap file, returns list of (stream, features, findings)."""
    dissector = TrafficDissector(pcap_path)
    flows = dissector.dissect()
    streams = StreamReconstructor.reconstruct(flows)
    email_streams = [s for s in streams if s.protocol in ("SMTP", "IMAP", "POP3")]

    results = []
    for stream in email_streams:
        seen, ok, _ = STARTTLSDetector.detect(stream)
        stream.starttls_seen, stream.starttls_upgrade_ok = seen, ok
        features = CryptoFeatureExtractor.extract(stream)
        findings = SecurityAssessor.assess(stream, features)
        results.append((stream, features, findings))
    return results


def build_dataset(labeled_dir: str, out_csv: str,
                   risk_labels_csv: Optional[str] = None):
    risk_label_map: Dict[str, str] = {}
    if risk_labels_csv and os.path.exists(risk_labels_csv):
        with open(risk_labels_csv) as f:
            reader = csv.DictReader(f)
            for row in reader:
                risk_label_map[row["filename"]] = row["risk_category"]

    rows = []
    for binary_label in ("normal", "malicious"):
        folder = os.path.join(labeled_dir, binary_label)
        if not os.path.isdir(folder):
            print(f"WARNING: expected folder not found, skipping: {folder}")
            continue

        for fname in os.listdir(folder):
            if not fname.lower().endswith((".pcap", ".pcapng")):
                continue
            full_path = os.path.join(folder, fname)
            print(f"Processing [{binary_label}] {fname} ...")
            try:
                stream_results = process_pcap(full_path)
            except RuntimeError as e:
                print(f"  ERROR (skipped): {e}")
                continue

            for stream, features, findings in stream_results:
                vec = vectorize(stream, features)
                risk_category = risk_label_map.get(
                    fname, _bootstrap_risk_category(findings)
                )
                rows.append({
                    **dict(zip(FEATURE_NAMES, vec)),
                    "binary_label": binary_label,
                    "risk_category": risk_category,
                    "source_file": fname,
                })

    if not rows:
        print("No rows produced -- check your folder layout and pcap files.")
        return

    with open(out_csv, "w", newline="") as f:
        fieldnames = FEATURE_NAMES + ["binary_label", "risk_category", "source_file"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} labeled rows to {out_csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Build a labeled training CSV from labeled PCAP captures."
    )
    parser.add_argument("labeled_dir", help="Folder containing normal/ and malicious/ subfolders")
    parser.add_argument("--out", default="training_data.csv", help="Output CSV path")
    parser.add_argument("--risk-labels", default=None,
                         help="Optional CSV (filename,risk_category) for the multiclass target")
    args = parser.parse_args()
    build_dataset(args.labeled_dir, args.out, args.risk_labels)


if __name__ == "__main__":
    main()
