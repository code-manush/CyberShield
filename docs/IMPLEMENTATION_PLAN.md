# CyberShield — Technical Implementation Plan

## 1. System Overview & Architecture
CyberShield is a production-grade, modular, real-time intrusion detection and prevention system (NIDPS) that monitors network traffic and authentication activity, detects suspicious behavior across three primary attack categories (Port Scanning, TCP SYN Flooding, and Brute-Force Authentication), scores threats using a centralized policy, stores structured security telemetry, executes configurable defensive responses via a safe firewall adapter, provides an evaluated Machine Learning classification engine, and delivers live real-time updates to a modern React + TypeScript dashboard.

```
                    ┌─────────────────────────┐
                    │ Network Traffic Sources │
                    │ (PCAP / Live Interface) │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │ Packet Sniffer / Parser │
                    │  (Async Queue & Filter) │
                    └───────────┬─────────────┘
                                │
            ┌───────────────────┴───────────────────┐
            ▼                                       ▼
  ┌───────────────────┐                   ┌───────────────────┐
  │ Port Scan Engine  │                   │ SYN Flood Engine  │
  │ (Sliding Window)  │                   │(Per-target rates) │
  └─────────┬─────────┘                   └─────────┬─────────┘
            │                                       │
            └───────────────────┬───────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────┐
  │          Centralized Threat Scoring Engine             │
  │  (Risk Score 0-100, Severity INFO/LOW/MED/HIGH/CRIT)   │
  └─────────────────────────────┬──────────────────────────┘
                                │
  ┌─────────────────────────────┼──────────────────────────┐
  │                             ▼                          ▼
  │                   ┌───────────────────┐      ┌───────────────────┐
  │                   │  ML Flow Engine   │      │  Response Engine  │
  │                   │  (Random Forest)  │      │ (Observe / Alert /│
  │                   └───────────────────┘      │     Enforce)      │
  │                                              └─────────┬─────────┘
  │                                                        │
  │  ┌─────────────────────────┐                           ▼
  │  │ Authentication Service  │                 ┌───────────────────┐
  │  │  (Normalized Ingestion) │                 │ Firewall Adapter  │
  │  └──────────┬──────────────┘                 │ (Simulated/Linux) │
  │             ▼                                └───────────────────┘
  │  ┌─────────────────────────┐
  │  │   Brute-Force Engine    │
  │  │ (Sliding Window Tracker)│
  │  └──────────┬──────────────┘
  │             │
  └─────────────┴───────────────────────────────┐
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │  SQLAlchemy Database  │
                                    │ (Security Events,     │
                                    │  Auth, Stats, Blocks) │
                                    └───────────┬───────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │ FastAPI + WebSockets  │
                                    └───────────┬───────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │   React + Vite + TS   │
                                    │    SOC Dashboard      │
                                    └───────────────────────┘
```

---

## 2. Modules to Reuse vs. Implement Independently

| Module | Design Strategy | Technical Implementation |
|--------|-----------------|--------------------------|
| **Sliding Window Tracker** | Independent implementation based on algorithmic principles | `SlidingWindow` using double-ended deque with timestamp expiration and `Counter` for $O(1)$ amortized frequency updates. |
| **Port Scan Detector** | Independent implementation | Tracks `(src_ip, dst_ip)` connection attempts with distinct port thresholding, sequential/random pattern classification, and cooldown timers. |
| **SYN Flood Detector** | Independent implementation | Tracks `(dst_ip, dst_port)` SYN packet rates (SYN set, ACK clear), source diversity calculation, rate calculations per second, cooldowns. |
| **Brute Force Detector** | Independent implementation | Consumes normalized authentication events, tracks failed attempts per `(source_ip, account)`, prevents credential exposure, sliding window tracking. |
| **Threat Scoring Engine** | Independent implementation | Explicit scoring function (0-100 scale, levels `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) based on frequency, diversity, persistence, and confidence. |
| **Response & Prevention Engine** | Independent implementation | Mode switching (`OBSERVE`, `ALERT`, `ENFORCE`), Lease/TTL-based blocking, allowlist enforcement (loopback, gateway, admin IPs), `FirewallAdapter` (Simulation vs Linux iptables). |
| **Machine Learning Engine** | Independent implementation | Supervised Random Forest trained on network flow features, reproducible training/eval script, feature extractor for live/PCAP flows, metrics reporting. |
| **Persistence Layer** | Independent implementation | SQLAlchemy models: `SecurityEvent`, `NetworkStatistic`, `AuthenticationEvent`, `BlockedAddress`, `AuditLog`. |
| **FastAPI REST & WebSocket** | Independent implementation | Full API with pagination, filtering, monitoring control, prevention actions, and live WebSocket broadcaster. |
| **React Dashboard** | Independent implementation | 6 pages: Security Overview, Live Monitoring, Threat Detection, Prevention Center, Machine Learning, Event Details. Dark SOC aesthetic, Recharts, Lucide React. |
| **Attack Simulation** | Independent implementation | Unit-testable synthetic traffic and authentication generation in a controlled test harness. |

---

## 3. Dependencies

### Backend Dependencies (`requirements.txt`)
- `fastapi>=0.110.0`
- `uvicorn[standard]>=0.28.0`
- `scapy>=2.5.0`
- `pydantic>=2.6.0`
- `pydantic-settings>=2.2.0`
- `sqlalchemy>=2.0.28`
- `scikit-learn>=1.4.1`
- `pandas>=2.2.1`
- `numpy>=1.26.4`
- `joblib>=1.3.2`
- `pytest>=8.1.1`
- `httpx>=0.27.0`
- `passlib[bcrypt]>=1.7.4`
- `python-multipart>=0.0.9`

### Frontend Dependencies (`package.json`)
- `react`, `react-dom` (React 18 / 19)
- `vite`
- `typescript`
- `lucide-react`
- `recharts`

---

## 4. Integration Risks & Mitigation Strategies

1. **Privilege & OS Differences (Windows vs Linux)**:
   - *Risk*: Raw socket packet sniffing and Linux `iptables` require root/admin privileges and are platform-dependent.
   - *Mitigation*: Offline PCAP analysis requires zero privileges. Live monitoring includes fallback and descriptive status messages. Prevention engine uses `SimulationFirewallAdapter` by default, providing full stateful block tracking, audit logging, and expiration without executing destructive host commands.
2. **Packet Processing Throughput & Queue Starvation**:
   - *Risk*: If packet capture synchronously writes to SQLite on every packet, the sniffer thread stalls.
   - *Mitigation*: Decoupled architecture with bounded queues; packet aggregation for network statistics (1-second time windows); detection rules evaluate lightweight in-memory sliding windows.
3. **Machine Learning Feature Mismatch**:
   - *Risk*: ML models trained on offline flow datasets cannot classify individual raw packets directly.
   - *Mitigation*: Explicit bidirectional Flow Feature Extractor (`FlowAggregator`) that summarizes bidirectional TCP/UDP/ICMP flows into feature vectors identical to the training schema (duration, src/dst bytes, packet counts, SYN ratio, service type).
4. **Credential Security**:
   - *Risk*: Logging passwords during brute-force testing.
   - *Mitigation*: Authentication endpoints and parsers immediately hash or discard passwords. Never store or display passwords in logs, database, or API.

---

## 5. Test Strategy
- **Unit Tests**:
  - `test_sliding_window.py`: Window expiration, distinct counting, memory pruning.
  - `test_port_scan.py`: Normal traffic vs scan, sequential vs random scan, cooldown enforcement.
  - `test_syn_flood.py`: Normal SYN vs flood, SYN-ACK exclusion, source diversity calculation.
  - `test_brute_force.py`: Normal login vs burst failures, account lockout, credential omission.
  - `test_threat_scoring.py`: Severity thresholds, score calculation formulas.
  - `test_prevention.py`: Mode enforcement, allowlist protection, temporary block expiration, audit logging.
- **API & WebSocket Tests**:
  - `test_api.py`: Health, system status, events CRUD, pagination, filtering, prevention actions, ML metrics.
- **Synthetic Packet & PCAP Tests**:
  - Offline capture generation (`sample_traffic.pcap`), verifying deterministic detection counts.
- **Integration Tests**:
  - End-to-end pipeline: packet -> detector -> threat score -> response engine -> database -> WebSocket broadcast.
