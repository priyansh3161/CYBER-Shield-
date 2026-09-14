# Cyber Shield / Cryptoscope
### AI-Assisted Email Cryptographic Forensics Framework

Email traffic (SMTP / IMAP / POP3 + modern Outlook 365 / Gmail over HTTPS) ko dono **live** aur **batch (PCAP)** mode me monitor karke, TLS/crypto hygiene issues detect karta hai — weak ciphers, deprecated TLS, STARTTLS-stripping, expired/self-signed certs, weak keys — aur unhe ek central dashboard pe risk-scored findings ke saath surface karta hai.

---

## Architecture

```
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
                  │  index.html (login)      │
                  │Cryptoscopedashboard.html │
                  └──────────────────────────┘
```

Dono engines (live C++ aur batch Python) independently apna-apna analysis karte hain lekin **same backend** pe data push karte hain, isliye dashboard pe live alerts aur uploaded-PCAP findings ek hi jagah dikhte hain.

---

## Components -> Files

| Component | File(s) | Kaam |
|---|---|---|
| Local real-time engine | `localengine.cpp` | Live interface sniff karta hai, STARTTLS-stripping / weak-TLS heuristics apply karta hai, suspicious events cloud ko bhejta hai |
| PCAP batch pipeline | `traffic_dissection.py`, `protocol_identifier.py`, `stream_reconstructor.py`, `starttls_detector.py`, `tls_handshake_parser.py`, `crypto_feature_extractor.py`, `security_assessor.py`, `ai_ml_analyzer.py`, `report_generator.py` | 9-stage forensic analysis of an uploaded `.pcap` file |
| Pipeline orchestrator | `main.py` | Saare 9 stages ko wire karta hai, CLI se bhi chal sakta hai |
| Shared data models | `models.py` | `TCPStream`, `CryptoFeatures`, `SecurityFinding`, `StreamVerdict` |
| ML feature schema | `feature_schema.py` | Training aur inference dono ke liye same numeric feature vector (drift se bachata hai) |
| Model training (optional) | `dataset_builder.py`, `train_model.py` | Labeled PCAPs se RandomForest classifiers train karna |
| Backend API | `app.py` | FastAPI: `/api/upload`, `/api/history`, `/api/analytics`, `/ws/live`, PDF report endpoint, Supabase integration |
| Login page | `index.html` | Neon/glassmorphism auth screen |
| Main dashboard | `Cryptoscopedashboard.html` | Live alerts, uploaded PCAP reports, analytics, PDF download |

---

## Setup

### 1. Python backend + batch pipeline

```bash
pip install -r requirements.txt
```

`requirements.txt` me: `fastapi`, `uvicorn`, `websockets`, `python-multipart`, `supabase`, `scapy`, `cryptography`, `scikit-learn`, `numpy`, `pandas`, `joblib`. PDF generation ke liye `reportlab` bhi chahiye (`app.py` isse import karta hai, `requirements.txt` me add karna na bhoolein).

Environment variables set karo (production ke liye zaroori):

```bash
export SUPABASE_URL="https://<your-project>.supabase.co"
export SUPABASE_KEY="<your-anon-or-service-key>"
```

> **Zaroori:** `app.py` me abhi ek fallback Supabase key hardcoded hai. Agar ye code kabhi public repo me commit hua hai, us key ko Supabase dashboard se turant rotate karo aur fallback hata ke sirf env var pe rely karo.

Backend chalao:

```bash
python app.py
# ya
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 2. Standalone batch pipeline (bina backend ke bhi)

```bash
python main.py capture.pcap --out report.json --html report.html
```

### 3. Local C++ real-time engine

```bash
sudo apt-get install libpcap-dev libcurl4-openssl-dev
g++ -O2 -std=c++17 localengine.cpp -o rt_engine -lpcap -lcurl -lpthread
sudo ./rt_engine eth0 https://<your-backend-host>/api/events
```

Self-test (interface ke bina):

```bash
./rt_engine --self-test
```

Windows ke liye Npcap SDK + libcurl chahiye — detail `localengine.cpp` ke top comment me hai.

### 4. Dashboard

`index.html` aur `Cryptoscopedashboard.html` ko kisi static host pe serve karo (ya seedha browser me kholo). Dashboard `Cryptoscopedashboard.html` ke andar `API_BASE` aur `WS_URL` constants apne backend URL se match karne chahiye.

> **Zaroori:** `index.html` ka login abhi ek hardcoded client-side check hai (`user === '3161' && pass === '3161'`), aur signup form kuch save nahi karta — dono cosmetic hai, real auth nahi. Production ke liye Supabase Auth (`signInWithPassword` / `signUp`) integrate karna padega.

---

## API Endpoints (app.py)

| Method | Path | Kaam |
|---|---|---|
| GET | `/` | Health/status |
| GET | `/api/health` | Simple health check |
| GET | `/api/history` | Recent alerts + threat_logs (Supabase se) |
| GET | `/api/analytics` | Charts ke liye raw alerts/threat_logs |
| GET | `/api/engine/status` | C++ engine online/offline status |
| POST | `/api/events` | C++ engine se suspicious event ingest |
| POST | `/api/engine/heartbeat` | C++ engine heartbeat |
| POST | `/api/upload` | `.pcap` upload -> 9-stage pipeline run -> JSON report |
| POST | `/api/pcap/report/pdf` | Ek report ka branded PDF generate karta hai |
| WS | `/ws/live` | Dashboard ke liye live broadcast channel |

---

## Detect kya hota hai

- Deprecated TLS (SSLv3 / TLS 1.0 / 1.1)
- Weak ciphers (RC4, 3DES, NULL, EXPORT, MD5)
- No forward secrecy (static RSA key exchange)
- Missing/failed STARTTLS upgrade (stripping attack indicator)
- Self-signed, expired, soon-to-expire certificates
- Weak key sizes (RSA < 2048 bit, EC < 224 bit)
- Weak signature algorithms (MD5/SHA-1 signed certs)
- Statistical anomalies via IsolationForest
- Outlook 365 / Gmail HTTPS traffic ko SNI se classify karke same heuristics apply karna

Har stream ko final **0-100 risk score** + **Critical/High/Medium/Low/Safe** classification milta hai, mitigation recommendations ke saath.

## (Optional) Apna model train karna

```bash
python dataset_builder.py labeled_captures/ --out training_data.csv
python train_model.py training_data.csv
```

Isse `models_store/binary_classifier.joblib` aur `models_store/risk_classifier.joblib` banega, jo agli baar `main.py`/`app.py` chalate hi `ai_ml_analyzer.py` automatically load kar lega — training zaroori nahi hai, rule-based scoring + IsolationForest bina training ke bhi kaam karta hai.

---

## Known Issues / TODO

- [ ] `app.py`: hardcoded Supabase key fallback hatao, sirf env var use karo
- [ ] `index.html`: real Supabase Auth se replace karo hardcoded `3161/3161` check ko
- [ ] `index.html`: signup form ko backend se connect karo (abhi kuch save nahi karta)
- [ ] `requirements.txt` me `reportlab` add karo (app.py use karta hai)
