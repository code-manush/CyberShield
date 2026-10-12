# CyberShield: AI-Assisted Real-Time Cyberattack Detection, Monitoring and Prevention System

CyberShield is an enterprise-grade, modular, real-time intrusion detection and prevention system (NIDPS). It combines high-throughput asynchronous network sniffing, sliding time-window rule engines, a trained machine-learning flow classifier, normalized authentication telemetry ingestion, stateful defense policy enforcement, and a modern React SOC dashboard.

---

## 1. Supported Attack Categories & Detection Engineering

CyberShield is purpose-built to detect, score, and mitigate three core cyberattack vectors:

### 1. Port Scanning
* **Detection Mechanism**: Tracks incoming TCP connection attempts (TCP `SYN` flag set and `ACK` flag cleared) across sliding observation windows per `(source_ip, destination_ip)` pair.
* **Algorithmic Complexity**: Amortized $O(1)$ sliding time-window using a double-ended queue paired with a frequency counter.
* **Pattern Classification**: Analyzes probed destination port distributions to classify scanning behavior:
  * **Sequential Scans**: Continuous consecutive port probes (e.g. ports 20–80).
  * **Common Service Probing**: Probing high-value target services (21, 22, 80, 443, 3306, 5432, 8080).
  * **Random Scans**: Randomized port distributions across ephemeral and registered ranges.
* **Thresholds**: Configurable defaults (e.g., 15 distinct ports within 10 seconds, 30s alert cooldown).

### 2. TCP SYN Flooding
* **Detection Mechanism**: Evaluates per-target `(destination_ip, destination_port)` SYN packet arrival rates. Excludes established connections (`SYN-ACK` responses and pure `ACK` data packets).
* **Source Diversity Analysis**:
  * **Single-Source Flood / High SYN Rate**: Many connection attempts originating from one address.
  * **Suspected Distributed SYN Flood**: SYN flood burst arriving from a diverse pool of spoofed addresses.
* **Thresholds**: Configurable defaults (e.g., 100 SYN packets within 5 seconds, 30s alert cooldown).

### 3. Brute-Force Authentication Attacks
* **Detection Mechanism**: Ingests normalized authentication telemetry events (source IP, targeted account, success/failure status, timestamp) rather than inspecting encrypted application payloads.
* **Pattern Tracking**: Tracks failures per `(source_ip, account)`, detecting both single-account password brute forcing and multi-account credential spraying.
* **Privacy & Security**: Zero plaintext credential retention. Passwords are never stored in the database, logged to disk, or exposed via API endpoints.
* **Mitigation**: Evaluates temporary IP lockout windows and triggers automated defense actions when configured.

---

## 2. System Architecture

```
                       ┌─────────────────────────┐
                       │  Network Traffic Source │
                       │ (Live Interface / PCAP) │
                       └───────────┬─────────────┘
                                   │
                                   ▼
                       ┌─────────────────────────┐
                       │ Packet Sniffer & Parser │
                       │  (Bounded Queue & BPF)  │
                       └───────────┬─────────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
       ┌───────────────────┐               ┌───────────────────┐
       │ Port Scan Engine  │               │  SYN Flood Engine │
       │ (Sliding Window)  │               │(Per-target rates) │
       └─────────┬─────────┘               └─────────┬─────────┘
                 │                                   │
                 └─────────────────┬─────────────────┘
                                   │
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │           Centralized Threat Scoring Engine            │
       │   (Risk Score 0-100, Severity INFO/LOW/MED/HIGH/CRIT)  │
       └───────────────────────────┬────────────────────────────┘
                                   │
       ┌───────────────────────────┼───────────────────────────┐
       │                           ▼                           ▼
       │                 ┌───────────────────┐       ┌───────────────────┐
       │                 │  ML Flow Engine   │       │  Response Engine  │
       │                 │  (Random Forest)  │       │ (Observe / Alert /│
       │                 └───────────────────┘       │     Enforce)      │
       │                                             └─────────┬─────────┘
       │                                                       │
       │  ┌─────────────────────────┐                          ▼
       │  │ Authentication Ingest   │                ┌───────────────────┐
       │  │ (Zero Password Leakage) │                │  Firewall Adapter │
       │  └──────────┬──────────────┘                │ (Simulated/Linux) │
       │             ▼                               └───────────────────┘
       │  ┌─────────────────────────┐
       │  │   Brute-Force Engine    │
       │  │ (Sliding Failure Rates) │
       │  └──────────┬──────────────┘
       │             │
       └─────────────┴───────────────────────────────┐
                                                     │
                                                     ▼
                                         ┌───────────────────────┐
                                         │  SQLAlchemy Database  │
                                         │  (SQLite/PostgreSQL)  │
                                         └───────────┬───────────┘
                                                     │
                                                     ▼
                                         ┌───────────────────────┐
                                         │ FastAPI REST & WS Bus │
                                         └───────────┬───────────┘
                                                     │
                                                     ▼
                                         ┌───────────────────────┐
                                         │   React + Vite + TS   │
                                         │     SOC Dashboard     │
                                         └───────────────────────┘
```

---

## 3. Technology Stack

* **Backend**: Python 3.11–3.13, FastAPI, Uvicorn, Scapy, Pydantic v2, SQLAlchemy, HTTPX.
* **Machine Learning**: scikit-learn (RandomForestClassifier), Pandas, NumPy, Joblib.
* **Database**: SQLite (default zero-config file database) with full PostgreSQL compatibility.
* **Real-time Delivery**: WebSockets (`/ws/events`).
* **Frontend**: React 18, Vite, TypeScript, Recharts, Lucide React, standard CSS modules.
* **Testing**: pytest (37 passing automated tests across detection, prevention, API, and integration).

---

## 4. Directory Structure

```
CyberShield/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application & WebSocket router
│   │   ├── core/                       # Configuration & structured logging
│   │   ├── database/                   # SQLAlchemy models & sessionmaker
│   │   ├── detection/                  # Sliding window, Port Scan, SYN Flood, Brute Force, Scoring
│   │   ├── monitoring/                 # Scapy parser, live sniffer, flow aggregator
│   │   ├── prevention/                 # Response engine & firewall adapters
│   │   ├── ml/                         # Flow feature schema & model classifier
│   │   ├── services/                   # Event router, auth service, WebSocket manager
│   │   └── api/                        # REST endpoints for health, monitoring, events, prevention, ml
│   ├── tests/                          # 37 automated unit and integration tests
│   └── requirements.txt                # Python backend dependencies
├── frontend/
│   ├── src/
│   │   ├── components/                 # Sidebar, Header, Metrics cards
│   │   ├── pages/                      # 6 SOC pages: Overview, Live, Threats, Prevention, ML, Detail
│   │   ├── services/                   # Typed API client & WebSocket hook
│   │   ├── types/                      # TypeScript definitions
│   │   └── styles/                     # Cybersecurity SOC dark styling
│   ├── package.json                    # Frontend dependencies
│   └── vite.config.ts                  # Vite development & proxy configuration
├── datasets/                           # Standardized network flow dataset
├── models/                             # Trained Random Forest model & metrics metadata
├── scripts/
│   ├── train_ml_model.py               # Reproducible ML training pipeline
│   ├── generate_test_pcap.py           # Synthetic PCAP test capture generator
│   └── simulate_attacks.py             # Controlled local attack generator
├── docs/
│   ├── REPOSITORY_AUDIT.md             # Candidate repository inspection report
│   └── IMPLEMENTATION_PLAN.md          # Architectural engineering plan
├── sample_traffic.pcap                 # Deterministic test capture file
└── README.md
```

---

## 5. Installation & Setup

### Prerequisites
* Python 3.11+ installed.
* Node.js v18+ and npm installed.
* Optional (for live packet capture on Windows): Npcap installed with WinPcap compatibility. (Offline PCAP analysis requires **no** administrative privileges or Npcap).

### 1. Backend Setup
```bash
# From project root
python -m venv .venv

# On Windows PowerShell:
.\.venv\Scripts\pip.exe install -r backend\requirements.txt

# On Linux/macOS:
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run build    # Verifies production TypeScript compilation
```

---

## 6. Running the System

### 1. Start the Backend API & WebSocket Server
```bash
# On Windows PowerShell:
$env:PYTHONPATH="backend"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload

# On Linux/macOS:
export PYTHONPATH="backend"
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
The backend API is now live at `http://127.0.0.1:8000` with interactive Swagger docs at `http://127.0.0.1:8000/docs`.

### 2. Start the Frontend Dashboard
In a second terminal:
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser to view the SOC dashboard.

---

## 7. Machine Learning Training & Evaluation

To reproduce the Random Forest model training and evaluation:
```bash
.\.venv\Scripts\python.exe scripts\train_ml_model.py
```

### Evaluation Results on Held-Out Test Data
* **Model Type**: `RandomForestClassifier` (100 estimators, max depth 12)
* **Dataset**: Standardized Network Flow Telemetry (6,000 samples, 80/20 train/test split)
* **Test Set Size**: 1,200 held-out flows
* **Accuracy**: **100.0%**
* **Macro F1-Score**: **1.0000**
* **False Positive Rate**: **0.0000**
* **Confusion Matrix**:
  ```text
  [[600,   0,   0],   # BENIGN
   [  0, 300,   0],   # PORT_SCAN
   [  0,   0, 300]]   # SYN_FLOOD
  ```
* **Top Flow Features**:
  1. `total_bwd_bytes` (14.2%)
  2. `total_bwd_packets` (11.8%)
  3. `ack_ratio` (11.8%)
  4. `syn_flag_count` (11.1%)
  5. `total_fwd_bytes` (9.6%)

The model and scaler are serialized to `models/random_forest_ids.joblib` and `models/scaler.joblib`. Evaluation metrics are stored in `models/ml_metrics.json`.

---

## 8. Network Monitoring & PCAP Replay

### Offline PCAP Analysis (Non-Privileged)
CyberShield includes a deterministic capture builder that generates `sample_traffic.pcap` containing 500 benign packets and realistic attack bursts:
```bash
# Generate deterministic sample capture
.\.venv\Scripts\python.exe scripts\generate_test_pcap.py

# Trigger PCAP analysis via API:
curl -X POST http://127.0.0.1:8000/api/monitoring/start \
     -H "Content-Type: application/json" \
     -d '{"pcap_path": "sample_traffic.pcap"}'
```
Or simply click **"Analyze PCAP"** on the **Live Monitoring** dashboard page.

### Live Packet Capture
To sniff on a live network adapter:
```bash
curl -X POST http://127.0.0.1:8000/api/monitoring/start \
     -H "Content-Type: application/json" \
     -d '{"interface": ""}'
```
Or click **"Start Live"** in the dashboard.
*Note*: On Windows, live packet sniffing requires Npcap with WinPcap API compatibility and elevated terminal privileges. If privileges are unavailable, offline PCAP analysis operates fully without restrictions.

---

## 9. Defensive Response Engine & Firewall Modes

The response engine operates in three selectable modes:

1. **`OBSERVE` (Default)**: Passive mode. Security threats are logged and visualized in real time. No firewall modifications occur.
2. **`ALERT`**: Threat alerts are pushed to the SOC dashboard and WebSocket clients with elevated severity indicators.
3. **`ENFORCE`**: Automated mitigation. Threats with high risk scores ($\ge 60.0$) automatically enact temporary, lease-based blocks against the offending source IP.

### Firewall Adapter Architecture
* **`SimulationFirewallAdapter` (Default on Windows & Dev)**: Models stateful IP blocks in SQLite storage and memory with lease expiration and audit logs without modifying host routing tables. Clearly distinguished in logs and UI as `SIMULATION`.
* **`LinuxIptablesAdapter` (Linux Production)**: Automatically executes scoped `iptables -A INPUT -s <ip> -j DROP -m comment --comment CyberShield-AutoBlock` rules with validation and expiration.

### Allowlist Safety Guarantees
The system **never** blocks:
* Loopback addresses (`127.0.0.1`, `::1`).
* Unspecified addresses (`0.0.0.0`).
* Configured management and trusted addresses (`TRUSTED_IPS`).

---

## 10. Attack Simulation & Testing

To test detection and mitigation locally without targeting external networks:

```bash
# 1. Simulate Brute-Force Authentication attack against /api/auth/login
.\.venv\Scripts\python.exe scripts\simulate_attacks.py --attack brute-force --attempts 15

# 2. Simulate normalized authentication event injection
.\.venv\Scripts\python.exe scripts\simulate_attacks.py --attack auth-inject --attempts 15
```
Watch the dashboard update immediately as brute force attempts trigger temporary account lockout and defensive blocking in ENFORCE mode!

---

## 11. Automated Test Suite

To run all 37 automated tests across unit detectors, threat scoring, prevention policies, and API integration:
```bash
# On Windows PowerShell:
$env:PYTHONPATH="backend"
.\.venv\Scripts\pytest.exe backend\tests -v

# On Linux/macOS:
export PYTHONPATH="backend"
pytest backend\tests -v
```
All 37 test cases execute deterministically and pass.

---

## 12. Known Limitations

* **IPv4 Scope**: Packet parsing and sliding window rules currently target IPv4 traffic. IPv6 packets are accounted for in protocol statistics but bypassed by IPv4-specific rules.
* **Encrypted Payloads**: HTTPS application-layer payloads are not decrypted. CyberShield analyzes network flow telemetry and TCP flag states rather than deep application layer payloads.
* **Stealthy Scans**: Extremely slow scans that probe fewer ports than the configured threshold over windows longer than the configured window duration will intentionally not trigger threshold alerts.
* **Privileged Raw Sockets**: Live packet sniffing requires administrator/root privileges or Npcap on Windows; offline PCAP analysis requires no privileges.

---

## 13. Candidate Repository Acknowledgments

In accordance with Phase 1 repository audit findings:
* **`network-traffic-ids` (adhilmohammedms)**: Inspected for sliding window algorithms and Scapy PCAP capture building. Concepts reimplemented cleanly.
* **`Intrusion_Detection_System` (Adhivishnu-18)**: Inspected for port scan categorization (sequential vs. random). Replaced monolithic iptables execution with the extensible `FirewallAdapter` pattern.
* **`threat-watch` (zeuu5)**: Inspected for authentication monitoring. Replaced in-memory counter and plaintext password logging with zero-credential-leakage normalized ingestion and sliding window failure analysis.

See [docs/REPOSITORY_AUDIT.md](docs/REPOSITORY_AUDIT.md) for full audit documentation.
