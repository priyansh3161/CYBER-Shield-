"""
report_generator.py
Stage 9: Findings, Risk Scores & Mitigation Recommendations

Serializes the final list of StreamVerdict objects into a structured
forensic report. Supports JSON (for the Supabase/FastAPI layer downstream)
and a lightweight standalone HTML view for quick human review.
"""

import json
from datetime import datetime, timezone
from typing import List
from dataclasses import asdict

from models import StreamVerdict


class ReportGenerator:
    @staticmethod
    def build_summary(verdicts: List[StreamVerdict]) -> dict:
        total = len(verdicts)
        by_class = {}
        for v in verdicts:
            by_class[v.risk_classification] = by_class.get(v.risk_classification, 0) + 1
        anomalies = sum(1 for v in verdicts if v.anomaly)

        return {
            "total_streams_analyzed": total,
            "risk_breakdown": by_class,
            "anomalous_streams": anomalies,
            "highest_risk_score": max((v.risk_score for v in verdicts), default=0),
        }

    @classmethod
    def to_json(cls, verdicts: List[StreamVerdict], pcap_source: str) -> str:
        report = {
            "meta": {
                "engine": "Cloud-Based Python Analysis Engine (PCAP)",
                "scan_mode": "batch_forensics",
                "engine_source": "cloud_python",
                "pcap_source": pcap_source,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "summary": cls.build_summary(verdicts),
            "findings": [
                {
                    **{k: v for k, v in asdict(sv).items() if k != "findings"},
                    "findings": [asdict(f) for f in sv.findings],
                }
                for sv in verdicts
            ],
        }
        return json.dumps(report, indent=2, default=str)

    @classmethod
    def to_html(cls, verdicts: List[StreamVerdict], pcap_source: str) -> str:
        summary = cls.build_summary(verdicts)
        severity_color = {
            "Critical": "#ff4d4f", "High": "#ff7a45", "Medium": "#faad14",
            "Low": "#52c41a", "Safe": "#13c2c2",
        }

        rows = []
        for v in verdicts:
            color = severity_color.get(v.risk_classification, "#888")
            finding_html = "<ul>" + "".join(
                f"<li><b>[{f.severity.upper()}] {f.category}:</b> {f.description}"
                f"<br><i>Recommendation:</i> {f.recommendation}</li>"
                for f in v.findings
            ) + "</ul>" if v.findings else "<i>No issues found.</i>"

            rows.append(f"""
            <tr>
              <td>{v.stream_id}</td>
              <td>{v.src_ip} &rarr; {v.dst_ip}</td>
              <td>{v.protocol or '-'}</td>
              <td>{v.tls_version or '-'}</td>
              <td>{v.cipher_suite or '-'}</td>
              <td style="color:{color}; font-weight:bold;">{v.risk_classification} ({v.risk_score})</td>
              <td>{'⚠️ Yes' if v.anomaly else 'No'}</td>
              <td>{finding_html}</td>
            </tr>
            """)

        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Forensic Report — {pcap_source}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0d1117; color:#e6edf3; padding:24px; }}
  h1 {{ font-size: 22px; }}
  .summary {{ display:flex; gap:16px; margin-bottom:24px; flex-wrap:wrap; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px 16px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ border:1px solid #30363d; padding:8px; text-align:left; vertical-align:top; }}
  th {{ background:#161b22; }}
  tr:nth-child(even) {{ background:#11151c; }}
</style>
</head>
<body>
  <h1>🔐 AI-Assisted Email Cryptographic Forensics Report</h1>
  <p>Source: <b>{pcap_source}</b> &nbsp;|&nbsp; Generated: {datetime.now(timezone.utc).isoformat()}</p>
  <div class="summary">
    <div class="card"><b>Total Streams:</b> {summary['total_streams_analyzed']}</div>
    <div class="card"><b>Anomalous Streams:</b> {summary['anomalous_streams']}</div>
    <div class="card"><b>Highest Risk Score:</b> {summary['highest_risk_score']}/100</div>
    <div class="card"><b>Breakdown:</b> {summary['risk_breakdown']}</div>
  </div>
  <table>
    <tr>
      <th>Stream ID</th><th>Endpoints</th><th>Protocol</th><th>TLS Version</th>
      <th>Cipher Suite</th><th>Risk</th><th>Anomaly</th><th>Findings & Mitigations</th>
    </tr>
    {''.join(rows)}
  </table>
</body>
</html>"""
