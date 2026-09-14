"""
main.py
Cloud-Based Python Analysis Engine (PCAP) — Orchestrator

Wires together all 9 stages of the PCAP Forensic Analysis Pipeline shown
in the architecture diagram:

  1. Traffic Dissection        -> traffic_dissection.py
  2. Protocol Identification   -> protocol_identifier.py
  3. TCP Stream Reconstruction -> stream_reconstructor.py
  4. STARTTLS Detection        -> starttls_detector.py
  5. TLS Handshake Parsing     -> tls_handshake_parser.py
  6. Crypto Feature Extraction -> crypto_feature_extractor.py
  7. Security Assessment       -> security_assessor.py
  8. AI/ML Analysis            -> ai_ml_analyzer.py
  9. Report Generation         -> report_generator.py

Usage:
    python main.py capture.pcap --out report.json --html report.html
"""

import argparse
import sys

from traffic_dissection import TrafficDissector
from stream_reconstructor import StreamReconstructor
from starttls_detector import STARTTLSDetector
from crypto_feature_extractor import CryptoFeatureExtractor
from security_assessor import SecurityAssessor
from ai_ml_analyzer import AIMLAnalyzer
from report_generator import ReportGenerator
from models import StreamVerdict


def run_pipeline(pcap_path: str):
    print(f"[1] Dissecting traffic from {pcap_path} ...")
    dissector = TrafficDissector(pcap_path)
    flows = dissector.dissect()
    print(f"    -> {len(flows)} TCP flow(s) found.")

    print("[2-3] Identifying protocols & reconstructing streams ...")
    streams = StreamReconstructor.reconstruct(flows)

    email_streams = [s for s in streams if s.protocol in ("SMTP", "IMAP", "POP3")]
    print(f"    -> {len(email_streams)} email-protocol stream(s) (SMTP/IMAP/POP3).")

    features_list = []
    all_findings_map = {}

    for stream in email_streams:
        print(f"[4] STARTTLS check for stream {stream.stream_id} ...")
        seen, ok, _offset = STARTTLSDetector.detect(stream)
        stream.starttls_seen = seen
        stream.starttls_upgrade_ok = ok

        print(f"[5-6] Parsing TLS handshake & extracting crypto features for {stream.stream_id} ...")
        features = CryptoFeatureExtractor.extract(stream)
        features_list.append(features)

        print(f"[7] Applying static security rules for {stream.stream_id} ...")
        findings = SecurityAssessor.assess(stream, features)
        all_findings_map[stream.stream_id] = findings

    print("[8] Running AI/ML risk scoring & anomaly detection ...")
    anomaly_map = AIMLAnalyzer.detect_anomalies(email_streams, features_list)

    if AIMLAnalyzer.models_available():
        print("    -> Trained supervised model(s) detected, blending predictions in.")

    verdicts = []
    for stream, features in zip(email_streams, features_list):
        findings = all_findings_map[stream.stream_id]
        risk_score = AIMLAnalyzer.compute_risk_score(findings)
        ml_predictions = AIMLAnalyzer.predict_with_trained_models(stream, features)
        verdicts.append(StreamVerdict(
            stream_id=stream.stream_id,
            src_ip=stream.src_ip,
            dst_ip=stream.dst_ip,
            protocol=stream.protocol,
            tls_version=features.tls_version,
            cipher_suite=features.cipher_suite,
            risk_score=risk_score,
            risk_classification=AIMLAnalyzer.classify(risk_score),
            anomaly=anomaly_map.get(stream.stream_id, False),
            findings=findings,
            ml_predictions=ml_predictions,
        ))

    print("[9] Generating report ...")
    return verdicts


def main():
    parser = argparse.ArgumentParser(
        description="Cloud-Based Python Analysis Engine — PCAP email cryptographic forensics."
    )
    parser.add_argument("pcap_file", help="Path to the .pcap file to analyze")
    parser.add_argument("--out", default="report.json", help="Output JSON report path")
    parser.add_argument("--html", default=None, help="Optional output HTML report path")
    args = parser.parse_args()

    try:
        verdicts = run_pipeline(args.pcap_file)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    json_report = ReportGenerator.to_json(verdicts, pcap_source=args.pcap_file)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json_report)
    print(f"JSON report written to {args.out}")

    if args.html:
        html_report = ReportGenerator.to_html(verdicts, pcap_source=args.pcap_file)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html_report)
        print(f"HTML report written to {args.html}")

    summary = ReportGenerator.build_summary(verdicts)
    print("\n=== SUMMARY ===")
    for k, v in summary.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
