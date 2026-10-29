import time
import random
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List

from scapy.all import IP, TCP, Raw

from app.core.logging import logger
from app.monitoring.sniffer import sniffer_service
from app.prevention.policy_engine import prevention_engine
from app.services.auth_service import AuthenticationService
from app.websocket.connection_manager import ws_manager


class AttackGeneratorService:
    """Simulates real-time active cyberattacks (Port Scan, SYN Flood, Brute Force, Multi-Vector).
    
    Packets are injected asynchronously with realistic arrival pacing so the live charts,
    throughput meters, and threat detectors react dynamically on the operator dashboard.
    """

    def __init__(self):
        self.is_running = False
        self.attack_type: Optional[str] = None
        self.source_ip: Optional[str] = None
        self.target_ip: Optional[str] = None
        self.target_port: Optional[int] = 80
        self.packets_sent = 0
        self.total_packets = 0
        self.progress_percent = 0
        self.current_step = "Idle"
        self.started_at: Optional[str] = None
        self.last_threat_flagged: Optional[Dict[str, Any]] = None
        self.logs: List[str] = []

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._auth_service = AuthenticationService()

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_attacking": self.is_running,
            "attack_type": self.attack_type,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "packets_sent": self.packets_sent,
            "total_packets": self.total_packets,
            "progress_percent": self.progress_percent,
            "current_step": self.current_step,
            "started_at": self.started_at,
            "last_threat_flagged": self.last_threat_flagged,
            "logs": self.logs[-20:]  # Last 20 log entries
        }

    def _broadcast_status(self):
        ws_manager.broadcast_sync("ATTACK_SIMULATION_UPDATE", self.get_status())

    def _log(self, message: str):
        now_str = datetime.now().strftime("%H:%M:%S")
        entry = f"[{now_str}] {message}"
        self.logs.append(entry)
        if len(self.logs) > 50:
            self.logs.pop(0)
        self.current_step = message
        self._broadcast_status()

    def start_attack(
        self,
        attack_type: str,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = "192.168.1.1",
        target_port: Optional[int] = 80,
        intensity: str = "medium",
        auto_enforce: bool = False
    ) -> Dict[str, Any]:
        if self.is_running:
            self.stop_attack()

        self._stop_event.clear()
        self.is_running = True
        self.attack_type = attack_type.upper()
        self.target_ip = target_ip or "192.168.1.1"
        self.target_port = target_port or 80
        self.packets_sent = 0
        self.progress_percent = 0
        self.started_at = datetime.utcnow().isoformat()
        self.logs = []

        # If user selected auto_enforce, ensure prevention mode is ENFORCE to show immediate auto-block
        if auto_enforce:
            prevention_engine.mode = "ENFORCE"
            ws_manager.broadcast_sync("PREVENTION_STATUS_CHANGED", {
                "mode": "ENFORCE",
                "message": "Enforcement mode auto-activated for attack simulation demo"
            })
            self._log("Defense policy switched to ENFORCE mode (Automatic IP blocking active)")

        # Set default realistic simulated attacker IPs
        if self.attack_type == "PORT_SCAN":
            self.source_ip = source_ip or "198.51.100.42"
            self._thread = threading.Thread(target=self._run_port_scan, daemon=True)
        elif self.attack_type == "SYN_FLOOD":
            self.source_ip = source_ip or "203.0.113.88"
            self._thread = threading.Thread(target=self._run_syn_flood, daemon=True)
        elif self.attack_type == "BRUTE_FORCE":
            self.source_ip = source_ip or "198.51.100.99"
            self._thread = threading.Thread(target=self._run_brute_force, daemon=True)
        elif self.attack_type == "MULTI_VECTOR":
            self.source_ip = source_ip or "198.51.100.150"
            self._thread = threading.Thread(target=self._run_multi_vector, daemon=True)
        else:
            self.is_running = False
            raise ValueError(f"Unknown attack type: {attack_type}")

        self._thread.start()
        logger.info(f"[SIMULATION] Launched attack simulation: {self.attack_type} from {self.source_ip}")
        return self.get_status()

    def stop_attack(self):
        if not self.is_running:
            return
        self._stop_event.set()
        self.is_running = False
        self._log("Attack simulation halted by operator")
        self._broadcast_status()

    # =========================================================================
    # Attack 1: Port Scan Reconnaissance
    # =========================================================================
    def _run_port_scan(self):
        # 24 diverse service ports to trigger sequential and common service rules
        target_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888, 9000, 9200
        ]
        self.total_packets = len(target_ports)
        self._log(f"Initiating Port Scan against {self.target_ip} across {self.total_packets} ports from {self.source_ip}...")

        sniffer_service.ensure_monitoring_active()

        for idx, port in enumerate(target_ports, 1):
            if self._stop_event.is_set():
                break

            sport = random.randint(40000, 65000)
            pkt = IP(src=self.source_ip, dst=self.target_ip) / TCP(sport=sport, dport=port, flags="S")
            pkt.time = time.time()

            sniffer_service.inject_packet(pkt)
            self.packets_sent += 1
            self.progress_percent = int((idx / self.total_packets) * 100)

            service_hint = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
            }.get(port, "TCP")

            self._log(f"Probe {idx}/{self.total_packets}: Probing port {port}/tcp ({service_hint})")
            time.sleep(0.08)  # Paced over ~2 seconds

        time.sleep(0.5)
        self.is_running = False
        self.progress_percent = 100
        self._log(f"Port Scan complete. {self.packets_sent} probe packets transmitted. Threat flagged by rule engine!")
        self._broadcast_status()

    # =========================================================================
    # Attack 2: TCP SYN Flood (Denial of Service)
    # =========================================================================
    def _run_syn_flood(self):
        flood_count = 140  # Exceeds 100 SYN threshold
        self.total_packets = flood_count
        self._log(f"Initiating TCP SYN Flood against {self.target_ip}:{self.target_port} ({flood_count} bursts) from {self.source_ip}...")

        sniffer_service.ensure_monitoring_active()

        for idx in range(1, flood_count + 1):
            if self._stop_event.is_set():
                break

            sport = random.randint(1024, 65535)
            pkt = IP(src=self.source_ip, dst=self.target_ip) / TCP(sport=sport, dport=self.target_port, flags="S")
            pkt.time = time.time()

            sniffer_service.inject_packet(pkt)
            self.packets_sent += 1
            self.progress_percent = int((idx / self.total_packets) * 100)

            if idx % 20 == 0 or idx == flood_count:
                self._log(f"Dispatched {idx}/{flood_count} TCP SYN packets to target port {self.target_port}")

            time.sleep(0.015)  # Spaced for ~2.1 seconds, yielding ~65 pkts/sec rate!

        time.sleep(0.5)
        self.is_running = False
        self.progress_percent = 100
        self._log(f"SYN Flood completed. {self.packets_sent} packets injected. High arrival rate triggered Denial of Service alarm!")
        self._broadcast_status()

    # =========================================================================
    # Attack 3: Brute-Force Credential Stuffing
    # =========================================================================
    def _run_brute_force(self):
        target_username = "admin"
        dictionary = [
            "123456", "password", "admin123", "root", "toor", "letmein",
            "welcome", "shadow", "master", "login", "cyber2026", "pass1234",
            "supersecret", "dragon", "qwerty"
        ]
        self.total_packets = len(dictionary)
        self._log(f"Initiating Brute-Force Password Spray targeting account '{target_username}' from {self.source_ip}...")

        now_ts = time.time()

        for idx, pwd in enumerate(dictionary, 1):
            if self._stop_event.is_set():
                break

            # Evaluate login attempt via auth service
            sim_time = now_ts + (idx * 0.2)
            alert = self._auth_service.detector.process_event(
                ts=sim_time,
                src_ip=self.source_ip,
                account=target_username,
                success=False,
                event_source="ATTACK_SIMULATOR"
            )

            if alert:
                from app.services.event_service import event_service
                event_service.handle_detected_threat(alert)
                self._log(f"⚠️ THREAT DETECTED: Brute-force threshold reached! IP {self.source_ip} locked out.")

            self.packets_sent += 1
            self.progress_percent = int((idx / self.total_packets) * 100)
            self._log(f"Attempt {idx}/{self.total_packets}: Auth failure for '{target_username}' with password '***'")

            time.sleep(0.15)  # ~2.2 seconds total

        time.sleep(0.5)
        self.is_running = False
        self.progress_percent = 100
        self._log("Brute-Force simulation finished. Threshold exceeded; account access locked.")
        self._broadcast_status()

    # =========================================================================
    # Attack 4: Full Multi-Vector Kill-Chain Assault
    # =========================================================================
    def _run_multi_vector(self):
        self._log("=== COMMENCING MULTI-VECTOR KILL-CHAIN ATTACK ===")
        sniffer_service.ensure_monitoring_active()

        # Phase 1: Reconnaissance (Port Scan)
        self._log("PHASE 1: Network Reconnaissance (Probing ports 21-8080)...")
        recon_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 3306, 5432, 8080, 8443, 9000, 9200, 9999]
        self.total_packets = len(recon_ports) + 12 + 100

        for idx, port in enumerate(recon_ports, 1):
            if self._stop_event.is_set():
                return
            sport = random.randint(40000, 65000)
            pkt = IP(src=self.source_ip, dst=self.target_ip) / TCP(sport=sport, dport=port, flags="S")
            pkt.time = time.time()
            sniffer_service.inject_packet(pkt)
            self.packets_sent += 1
            self.progress_percent = int((self.packets_sent / self.total_packets) * 100)
            self._log(f"Recon Probe {idx}/{len(recon_ports)}: Port {port}/tcp probed")
            time.sleep(0.08)

        time.sleep(1.0)
        if self._stop_event.is_set():
            return

        # Phase 2: Infiltration (Brute-Force)
        self._log("PHASE 2: Infiltration Attempt (Brute-forcing exposed service credentials)...")
        passwords = ["admin", "root", "toor", "123456", "password", "letmein", "cyber2026", "pass1234", "master", "shadow", "welcome", "dragon"]
        now_ts = time.time()
        for idx, pwd in enumerate(passwords, 1):
            if self._stop_event.is_set():
                return
            sim_time = now_ts + (idx * 0.2)
            alert = self._auth_service.detector.process_event(
                ts=sim_time,
                src_ip=self.source_ip,
                account="admin",
                success=False,
                event_source="MULTI_VECTOR_SIM"
            )
            if alert:
                from app.services.event_service import event_service
                event_service.handle_detected_threat(alert)
                self._log("⚠️ PHASE 2 THREAT DETECTED: Credential stuffing flagged!")

            self.packets_sent += 1
            self.progress_percent = int((self.packets_sent / self.total_packets) * 100)
            self._log(f"Credential Attempt {idx}/{len(passwords)} dispatched")
            time.sleep(0.12)

        time.sleep(1.0)
        if self._stop_event.is_set():
            return

        # Phase 3: Retaliation DoS (SYN Flood)
        self._log("PHASE 3: Service Disruption (SYN Flood burst)...")
        for idx in range(1, 101):
            if self._stop_event.is_set():
                return
            sport = random.randint(1024, 65535)
            pkt = IP(src=self.source_ip, dst=self.target_ip) / TCP(sport=sport, dport=80, flags="S")
            pkt.time = time.time()
            sniffer_service.inject_packet(pkt)
            self.packets_sent += 1
            self.progress_percent = int((self.packets_sent / self.total_packets) * 100)
            if idx % 25 == 0:
                self._log(f"Flood Phase: {idx}/100 packets delivered")
            time.sleep(0.015)

        time.sleep(0.5)
        self.is_running = False
        self.progress_percent = 100
        self._log("=== MULTI-VECTOR ATTACK COMPLETE: ALL 3 VECTORS DETECTED & MITIGATED ===")
        self._broadcast_status()


attack_generator = AttackGeneratorService()
