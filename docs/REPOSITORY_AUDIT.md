# Repository Audit Report — CyberShield Candidate Codebases

This document records the thorough inspection and technical audit of candidate repositories evaluated for the CyberShield project, in compliance with licensing guidelines, engineering constraints, and security requirements.

---

## 1. Candidate Repository Overview

| Identifier | Repository URL | Verified Branch | Primary Stated Purpose |
|------------|----------------|-----------------|------------------------|
| **Repo A** | [https://github.com/adhilmohammedms/network-traffic-ids](https://github.com/adhilmohammedms/network-traffic-ids) | `main` | Network Traffic Analyzer & IDS using Scapy, sliding time windows, and PCAP analysis |
| **Repo B** | [https://github.com/Adhivishnu-18/Intrusion_Detection_System](https://github.com/Adhivishnu-18/Intrusion_Detection_System) | `main` | NIDPS with port scan & OS fingerprinting detection, iptables blocking, CLI menu |
| **Repo C** | [https://github.com/zeuu5/threat-watch](https://github.com/zeuu5/threat-watch) | `main` | ThreatWatch Flask simulation for brute force, SQLi, XSS, and basic in-memory locking |

---

## 2. In-Depth Repository Evaluation

### Repository A: `network-traffic-ids` (adhilmohammedms)
* **Accessibility**: Successfully cloned via Git (`--depth 1`).
* **License Information**: **No explicit LICENSE file** present in repository root or source files. Under GitHub terms and standard copyright law, direct verbatim copying of proprietary source files cannot be licensed without explicit permission. Therefore, algorithmic concepts are adopted and cleanly reimplemented in CyberShield.
* **Architecture & Dependencies**:
  * Dependencies: Python 3, `scapy` (specifically `PcapReader`, `sniff`, `IP`, `TCP`, `UDP`, `ICMP`).
  * Architecture: Single-file procedural/class script (`ids.py`) + synthetic capture builder (`make_test_pcap.py`).
* **Features Verified in Source**:
  * Efficient $O(1)$ amortized sliding-window tracker (`SlidingWindow`) pairing a `collections.deque` of `(timestamp, value)` with a `collections.Counter`.
  * TCP SYN connection attempt filtering (`flags & TCP_SYN and not flags & TCP_ACK`).
  * Port scan detection thresholding: Tracking `(src, dst)` mapping to unique destination ports.
  * SYN flood detection: Keying on `(dst, dport)` mapping to source IPs with sliding window counts and source diversity calculation.
  * Deterministic packet timestamp processing (allowing offline PCAP replay independent of real-time clock drift).
  * Pruning of idle windows every $N$ packets.
* **Limitations Identified**:
  * IPv4 only.
  * Command-line only output; no API, no WebSockets, no database persistence, no authentication monitoring.
  * Memory pruning is based on packet counter interval, which is unbuffered for asynchronous web systems.
* **Selected for CyberShield**:
  * Adopt the sliding window algorithmic design (deque + Counter) for our backend detection engine.
  * Adopt the packet crafting concept from `make_test_pcap.py` to generate authentic PCAP test files for offline validation and automated test suites.

---

### Repository B: `Intrusion_Detection_System` (Adhivishnu-18)
* **Accessibility**: Successfully cloned via Git (`--depth 1`).
* **License Information**: **No explicit LICENSE file** present in repository. Code was submitted as an academic assignment. All functionality will be independently implemented.
* **Architecture & Dependencies**:
  * Dependencies: Python 3, `scapy` (`AsyncSniffer`, `sniff`, `IP`, `TCP`, `get_if_list`).
  * Linux-specific command invocation: hardcoded `iptables -A INPUT -s <ip> -j DROP`.
* **Features Verified in Source**:
  * Multi-interface sniffing using `AsyncSniffer`.
  * Sequential vs. random port scan analysis (`_analyze_scan_type`, `_is_sequential`, `_is_incremental`).
  * Horizontal scan detection (one source probing many distinct destinations).
  * OS fingerprinting detection through TCP flag combination variations (SYN, FIN, ACK, etc.).
  * Automated blocking via iptables CLI commands.
* **Limitations & Architectural Incompatibilities**:
  * **Critical Platform Limitation**: Hardcoded for Linux iptables. On Windows or without root permissions, `subprocess.run(["iptables", ...])` throws execution errors.
  * **Security Vulnerabilities**:
    * No IP format validation or sanitization before command execution.
    * No allowlist mechanism: could easily block `127.0.0.1`, default gateway, or administrator IP.
    * Permanent blocking with no lease or expiration duration.
    * Synchronous execution during packet callback can stall packet sniffing thread.
  * Monolithic terminal menu interface (`input()`), incompatible with web-based SOC operations.
* **Selected for CyberShield**:
  * Implement an abstract **Firewall Adapter Pattern**:
    * `SimulationFirewallAdapter` (cross-platform, development, Windows-safe, non-destructive).
    * `LinuxIptablesAdapter` (strict input validation, reversible, scoped with comments and automatic timeouts).
  * Port scan classification logic (sequential, incremental, random, distributed) integrated into threat scoring and metadata.
  * Strict allowlist enforcement and temporary block lease expiration.

---

### Repository C: `threat-watch` (zeuu5)
* **Accessibility**: Successfully cloned via Git (`--depth 1`).
* **License Information**: **No explicit LICENSE file** present in repository. Features will be implemented independently.
* **Architecture & Dependencies**:
  * Dependencies: Flask, Werkzeug, Flask-Limiter, requests.
  * Architecture: Monolithic Flask application with server-rendered Jinja templates and plain text file logs (`logs.txt`).
* **Features Verified in Source**:
  * Authentication login endpoint (`POST /` in `app/routes/auth.py`).
  * Attack simulation script (`attacks/bruteforce.py`) targeting the login route.
  * In-memory counter for failed login attempts (`failed_attempts.setdefault(username, 0)`).
* **Limitations & Security Deficiencies**:
  * **Severe Security Flaw**: Logged plaintext passwords into `logs.txt` and terminal output (`log_attempt(ip, username, password, ...)`).
  * **Flawed Detection Logic**:
    * Does not use a sliding time window. A user failing 5 times across 3 weeks gets flagged as a brute-force attacker.
    * Keyed primarily by username rather than `(source_ip, username)` or tracking multi-account password spraying.
  * Flask + HTML templates do not satisfy the required modern FastAPI + React + WebSocket real-time architecture.
* **Selected for CyberShield**:
  * Independent implementation of a normalized **Authentication Event Ingestion Service**.
  * True sliding-window brute-force detector tracking failure rates per IP and multi-account targeting (spraying vs single-target brute force).
  * Zero-plaintext logging: passwords discarded immediately after hash evaluation; only security event metadata persisted.
  * Safe attack simulation scripts for generating authenticated login tests.

---

## 3. Summary of Code Reuse & Independent Implementations

| Component | Strategy | Source / Rationale |
|-----------|----------|-------------------|
| **Sliding Window Tracker** | Independent implementation based on algorithmic principles | Clean Python class using `deque` + `Counter` with time-based pruning (inspired by Repo A). |
| **Port Scan Engine** | Independent implementation | Enhanced with sequential/random analysis, distinct port tracking, configurable windows/cooldowns. |
| **SYN Flood Engine** | Independent implementation | Destination-keyed rate tracking with source diversity calculation. |
| **Brute Force Engine** | Independent implementation | Sliding window failure rates, zero credential leakage, account lockout state. |
| **Prevention Engine** | Independent implementation | Modular adapter architecture (`SimulationAdapter`, `LinuxFirewallAdapter`), lease expiration, allowlist safety. |
| **Machine Learning** | Independent implementation | Supervised Random Forest trained on realistic network flow features, evaluation report, and feature extractor. |
| **Database & API** | Independent implementation | SQLAlchemy models (SQLite/PostgreSQL compatible), FastAPI REST API, WebSocket pub/sub. |
| **Frontend UI** | Independent implementation | React + Vite + TypeScript SOC dashboard with Recharts and Lucide React. |
| **Attack Simulation** | Independent implementation | Safe local generators for Port Scan, SYN Flood, and Brute Force authentication. |

All code written for CyberShield is original, clean, well-tested, and respects open-source licensing principles.
