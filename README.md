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

## Getting Started

### Prerequisites

- **Python:** 3.9 or higher
- **C++ Compiler:** `g++` (C++17 support required)
- **Libraries (Linux):** `libpcap-dev`, `libcurl4-openssl-dev`

---

### Installation & Setup

#### 1. Backend Service Setup

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Set environment variables for Supabase database access:

```bash
export SUPABASE_URL="https://<your-project>.supabase.co"
export SUPABASE_KEY="<your-service-key>"
```

Start the FastAPI application:

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

#### 2. Local Real-Time C++ Engine

Install required capture packages (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install libpcap-dev libcurl4-openssl-dev
```

Compile and run the binary:

```bash
g++ -O2 -std=c++17 localengine.cpp -o rt_engine -lpcap -lcurl -lpthread
sudo ./rt_engine eth0 https://<your-backend-host>/api/events
```

Run self-test diagnostics without live network interfaces:

```bash
./rt_engine --self-test
```

*(Note: For Windows deployment, ensure Npcap SDK and libcurl are installed and linked).*

#### 3. Standalone PCAP Analysis (CLI)

Run forensic analysis on a captured file without launching the web server:

```bash
python main.py sample_capture.pcap --out report.json --html report.html
```

---

## API Documentation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service root and health check |
| `GET` | `/api/health` | Standard status endpoint |
| `GET` | `/api/history` | Fetches historical security alerts and threat logs |
| `GET` | `/api/analytics` | Returns aggregated metrics for dashboard visualizers |
| `GET` | `/api/engine/status` | Reports the health status of the real-time C++ engine |
| `POST` | `/api/events` | Ingests real-time events from the C++ engine |
| `POST` | `/api/engine/heartbeat` | C++ engine heartbeat check |
| `POST` | `/api/upload` | Uploads `.pcap` files for 9-stage forensic processing |
| `POST` | `/api/pcap/report/pdf` | Generates a branded PDF report for a completed analysis |
| `WS` | `/ws/live` | WebSocket endpoint for broadcasting live security events |

---

## Detection Scope

Cryptoscope identifies and flags the following security indicators:

- **Deprecated Protocols:** SSLv3, TLS 1.0, and TLS 1.1 usages.
- **Weak Ciphers:** RC4, 3DES, NULL, EXPORT, MD5 cipher suites.
- **Missing Forward Secrecy:** Usage of static RSA key exchange algorithms.
- **STARTTLS Downgrades:** Insecure plain-text negotiation or stripping attacks.
- **Certificate Vulnerabilities:** Expired, self-signed, weak signature (MD5/SHA1), or insufficient key lengths (RSA < 2048-bit, EC < 224-bit).
- **Anomalous Traffic:** Statistical deviations scored via an unsupervised Isolation Forest model.

Each stream is assigned an aggregated **0–100 Risk Score** and mapped to a severity tier (`Critical`, `High`, `Medium`, `Low`, `Safe`).

---

## Machine Learning Integration 

In addition to heuristic rule evaluation and Isolation Forests, custom supervised models can be trained:

```bash
python dataset_builder.py labeled_captures/ --out training_data.csv
python train_model.py training_data.csv
```

Compiled model artifacts (`.joblib`) placed in `models_store/` are automatically loaded during pipeline execution.

---


