# Cloud-Based Python Analysis Engine (PCAP)

Diagram ke green box ("CLOUD-BASED PYTHON ANALYSIS ENGINE") ka poora implementation —
9-stage PCAP forensic pipeline for email cryptographic analysis (SMTP/IMAP/POP3 + TLS).

## Stages -> Files

| # | Stage | File |
|---|-------|------|
| 1 | Traffic Dissection (Scapy) | `traffic_dissection.py` |
| 2 | Protocol Identification | `protocol_identifier.py` |
| 3 | TCP Stream Reconstruction | `stream_reconstructor.py` |
| 4 | STARTTLS Detection & Transitions | `starttls_detector.py` |
| 5 | TLS Handshake Parsing | `tls_handshake_parser.py` |
| 6 | Cryptographic Feature Extraction | `crypto_feature_extractor.py` |
| 7 | Security Assessment (Static Rules) | `security_assessor.py` |
| 8 | AI/ML Analysis (Risk score, anomaly detection) | `ai_ml_analyzer.py` |
| 9 | Findings, Risk Scores & Report | `report_generator.py` |

`main.py` orchestrates all 9 stages end-to-end.
`models.py` holds shared dataclasses (`TCPStream`, `CryptoFeatures`, `SecurityFinding`, `StreamVerdict`).

## Setup

```bash
pip install -r requirements.txt
```

> Is sandbox mein internet access nahi tha isliye `scapy` install nahi ho paya —
> apne machine/server pe upar wala command chalate hi ye turant kaam karega.
> Baaki sab (`cryptography`, `scikit-learn`, `numpy`) yahin verify kiya gaya hai.

## Usage

```bash
python main.py capture.pcap --out report.json --html report.html
```

Output:
- `report.json` — Supabase/FastAPI layer ke liye structured JSON (diagram ke "Shared Database Layer" me jaane wala format)
- `report.html` — quick standalone visual report kholne ke liye

## Kya detect hota hai

- Deprecated TLS (SSLv3 / TLS 1.0 / 1.1)
- Weak ciphers (RC4, 3DES, NULL, EXPORT, MD5)
- No forward secrecy (static RSA key exchange)
- Missing/failed STARTTLS upgrade (possible stripping attack)
- Self-signed, expired, soon-to-expire certificates
- Weak key sizes (RSA < 2048 bit, EC < 224 bit)
- Weak signature algorithms (MD5/SHA-1 signed certs)
- Statistical anomalies via IsolationForest (unusual packet count, session duration, TLS version/key-size combo across the whole batch)

Har stream ko final **0-100 risk score** + **Critical/High/Medium/Low/Safe** classification milta hai, saath me mitigation recommendations.

## (Optional) Apna model train karna

Training zaroori nahi hai — pipeline bina training ke bhi chalta hai (rule-based risk
score + IsolationForest anomaly detection). Lekin agar aapke paas labeled data hai
(jaise CICIDS2017/ISCX/MCFP se pcaps, ya apni khud ki labeled captures), to:

**Step 1 — Folder banao:**
```
labeled_captures/
    normal/
        capture1.pcap
        capture2.pcap
    malicious/
        phishing1.pcap
        c2_beacon.pcap
```

**Step 2 — Features + labels wali CSV banao (same pipeline se, consistent schema):**
```bash
python dataset_builder.py labeled_captures/ --out training_data.csv
```
Agar risk-category (Critical/High/Medium/Low/Safe) ka apna ground-truth label hai to:
```bash
python dataset_builder.py labeled_captures/ --out training_data.csv --risk-labels risk_labels.csv
```
(`risk_labels.csv` format: `filename,risk_category`). Agar nahi diya, to system khud
Stage 7 ke static rules se ek bootstrap label bana leta hai.

**Step 3 — Train karo:**
```bash
python train_model.py training_data.csv
```
Ye do models bana ke `models_store/` folder me save karega:
- `binary_classifier.joblib` (malicious vs normal)
- `risk_classifier.joblib` (Critical/High/Medium/Low/Safe)

**Step 4 — Bas, kuch aur karna nahi hai.** Agli baar `main.py` chalate hi
`ai_ml_analyzer.py` automatically `models_store/` se dono models load kar lega aur
har stream ke `ml_predictions` field me `ml_malicious_probability` +
`ml_risk_category` add ho jayega — bina training ke bhi (agar models_store/ khali ho)
sab kuch pehle jaisa hi chalega, kuch break nahi hoga.

## Integration Notes (aage ke liye)

- `ReportGenerator.to_json()` ka output seedha FastAPI backend se Supabase (`threat_logs`,
  `tls_sessions`, `certificates`, `alerts` tables) me push karne ke liye ready hai — bas
  `scan_mode="batch_forensics"` aur `engine_source="cloud_python"` tags already `meta` block me maujood hain jaisa diagram me mention hai.
- Live engine (C++ real-time) se aane wale "Suspicious Event" bhi isi pipeline ke stage 4-9
  (STARTTLS parsing se aage) me feed kiye ja sakte hain — sirf `TCPStream` object bana ke
  `raw_client_bytes` / `raw_server_bytes` fill karna hoga, baaki pipeline same reuse hoga.
