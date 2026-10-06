# Cyber Shield / Cryptoscope
> **AI-Assisted Email Cryptographic Forensics Framework**

Cryptoscope is a comprehensive cryptographic forensics framework designed to monitor and evaluate email traffic (SMTP, IMAP, POP3, and modern Outlook 365/Gmail over HTTPS). Operating in both **live** and **batch (PCAP)** modes, it detects TLS and cryptographic hygiene vulnerabilities—such as weak ciphers, deprecated TLS versions, STARTTLS-stripping attacks, expired/self-signed certificates, and weak cryptographic keys. All findings are surfaced on a centralized web dashboard with detailed AI-assisted risk scoring and mitigation recommendations.

---

## Key Features

- **Dual-Engine Architecture:** Real-time live traffic capture via a high-performance C++ engine alongside a deep forensic 9-stage Python batch pipeline for PCAPs.
- **Protocol & Traffic Coverage:** Support for legacy email protocols (SMTP, IMAP, POP3) as well as HTTPS-based webmail/cloud services (Outlook 365, Gmail via SNI classification).
- **Comprehensive Crypto Auditing:** Detects weak/deprecated TLS versions, weak cipher suites, static RSA key exchanges, weak certificate signatures, and key size deficiencies.
- **Active Interception Detection:** Identifies STARTTLS stripping attempts and suspicious handshake downgrades.
- **AI/ML Risk Scoring:** Blends deterministic heuristic scoring with machine learning (Isolation Forest for anomaly detection and optional supervised classifiers).
- **Centralized Dashboard:** Real-time alert feed via WebSockets, historical threat analytics, and automated PDF forensic report generation.

---

## System Architecture

```text
┌─────────────────────────┐        ┌──────────────────────────┐
│  LOCAL C++ ENGINE       │        │  CLOUD PYTHON ENGINE     │
│  (Live Traffic Path)    │        │  (Batch PCAP Forensics)  │
│                         │        │                          │
│1. Packet Capture        │        │1. Traffic Dissection     │
│   (libpcap / Npcap)     │        │2. Protocol Identification│
│2. Protocol ID           │        │3. TCP Stream Reconstruct │
│  (SMTP/IMAP/POP3 +      │        │4. STARTTLS Detection     │
│   443 via SNI)          │        │5. TLS Handshake Parsing  │
│3. STARTTLS Detection    │        │6. Crypto Feature Extract │
│4. Heuristic Checks      │        │7. Security Assessment    │
│5. Suspicious Event Gate │        │8. AI/ML Risk Scoring     │
│6. Fast Local Actions    │        │9. Report Generation      │
│  7. POST -> Cloud API   |        │                          │
└────────────┬────────────┘        └─────────────┬────────────┘
             │  HTTPS (/api/events,              │  HTTPS (/api/upload)
             │   /api/engine/heartbeat)          │
             └───────────────┬───────────────────┘
                             ▼
                  ┌────────────────────────┐
                  │  FastAPI Backend       │
                  │  (app.py)              │
                  │ - REST API             │
                  │ - WebSocket (/ws/live) │
                  │ - PDF report generation│
                  └────────────┬───────────┘
                               ▼
                  ┌──────────────────────────┐
                  │Supabase (Postgres)       │
                  │threat_logs, alerts,      │
                  │tls_sessions, certificates│
                  └────────────┬─────────────┘
                               ▼
                  ┌──────────────────────────┐
                  │   Web Dashboard          │
                  │   index.html (login)     │
                  │Cryptoscopedashboard.html │
                  └──────────────────────────┘
```

Both engines operate independently but stream structured telemetry and security findings to a unified REST API and Supabase database backend.

---

## Component Overview

| Component | Main File(s) | Functionality |
|---|---|---|
| **Real-Time Engine** | `localengine.cpp` | Captures live interface traffic, evaluates STARTTLS and TLS handshake heuristics, and alerts backend APIs. |
| **PCAP Forensic Engine** | `traffic_dissection.py`<br>`protocol_identifier.py`<br>`stream_reconstructor.py`<br>`starttls_detector.py`<br>`tls_handshake_parser.py`<br>`crypto_feature_extractor.py`<br>`security_assessor.py`<br>`ai_ml_analyzer.py`<br>`report_generator.py` | Executes a modular 9-stage deep forensic analysis on uploaded `.pcap` capture files. |
| **Pipeline Orchestrator** | `main.py` | CLI controller that coordinates the 9-stage forensic pipeline. |
| **Data Models & Schema** | `models.py`<br>`feature_schema.py` | Core data models and a standardized numerical schema for ML feature vectors. |
| **ML Training Utilities** | `dataset_builder.py`<br>`train_model.py` | Scripts to extract feature sets from PCAPs and train custom ML models. |
| **Backend Service** | `app.py` | FastAPI backend managing endpoints, WebSockets, Supabase integration, and PDF exports. |
| **User Interface** | `index.html`<br>`Cryptoscopedashboard.html` | Frontend interface for monitoring real-time telemetry, viewing reports, and analyzing security metrics. |

---

