import time
import threading
import queue
import os
from collections import Counter, deque
from datetime import datetime
from typing import Optional, List, Dict, Any

from scapy.all import get_if_list, sniff, PcapReader
from scapy.error import Scapy_Exception

from app.core.config import settings
from app.core.logging import logger
from app.database.session import SessionLocal
from app.database.models import NetworkStatistic
from app.monitoring.packet_parser import PacketParser
from app.monitoring.flow_aggregator import FlowAggregator
from app.detection.port_scan import PortScanDetector
from app.detection.syn_flood import SynFloodDetector
from app.services.event_service import event_service
from app.websocket.connection_manager import ws_manager


class NetworkSnifferService:
    """Manages live packet sniffing and offline PCAP playback with bounded queues."""

    def __init__(self):
        self.is_running = False
        self.mode = "IDLE"  # IDLE, LIVE_CAPTURE, PCAP_REPLAY
        self.interface: Optional[str] = None
        self.pcap_path: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.error_message: Optional[str] = None

        # Detectors
        self.port_scan_detector = PortScanDetector(
            threshold_ports=settings.PORT_SCAN_THRESHOLD,
            window_seconds=settings.PORT_SCAN_WINDOW_SECONDS,
            cooldown_seconds=settings.PORT_SCAN_COOLDOWN_SECONDS
        )
        self.syn_flood_detector = SynFloodDetector(
            threshold_syns=settings.SYN_FLOOD_THRESHOLD,
            window_seconds=settings.SYN_FLOOD_WINDOW_SECONDS,
            cooldown_seconds=settings.SYN_FLOOD_COOLDOWN_SECONDS
        )
        self.flow_aggregator = FlowAggregator()

        # Queues and threading
        self.packet_queue = queue.Queue(maxsize=settings.MAX_PACKET_QUEUE_SIZE)
        self.capture_thread: Optional[threading.Thread] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.stats_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Telemetry counters
        self.packets_captured = 0
        self.bytes_captured = 0
        self.protocol_counts = Counter()
        self.talkers = Counter()
        self.dest_ports = Counter()

        # Rate calculations (sliding 1-second buckets)
        self.recent_packet_times = deque()  # (timestamp, byte_count)
        self.history_samples = deque(maxlen=60)  # last 60 seconds of pps/bps

    def get_available_interfaces(self) -> List[str]:
        try:
            return get_if_list()
        except Exception as e:
            logger.warning(f"Failed to list network interfaces: {e}")
            return []

    def start_offline(self, pcap_path: str) -> bool:
        """Start playback analysis of an offline PCAP/PCAPNG file."""
        if self.is_running:
            self.stop()

        if not os.path.exists(pcap_path):
            self.error_message = f"PCAP file not found: {pcap_path}"
            return False

        self.reset_state()
        self.mode = "PCAP_REPLAY"
        self.pcap_path = pcap_path
        self.is_running = True
        self.start_time = datetime.utcnow()
        self._stop_event.clear()

        # Launch worker
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

        # Launch pcap reader
        self.capture_thread = threading.Thread(target=self._pcap_reader_loop, args=(pcap_path,), daemon=True)
        self.capture_thread.start()

        # Launch telemetry aggregator
        self.stats_thread = threading.Thread(target=self._stats_aggregator_loop, daemon=True)
        self.stats_thread.start()

        logger.info(f"[MONITORING] Started offline PCAP replay of {pcap_path}")
        return True

    def start_live(self, interface: Optional[str] = None, bpf_filter: str = "ip") -> bool:
        """Start real-time packet capture on the selected network interface."""
        if self.is_running:
            self.stop()

        self.reset_state()
        self.mode = "LIVE_CAPTURE"
        self.interface = interface or settings.DEFAULT_INTERFACE or None
        self.is_running = True
        self.start_time = datetime.utcnow()
        self._stop_event.clear()

        # Launch worker thread
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

        # Launch live capture thread
        self.capture_thread = threading.Thread(target=self._live_capture_loop, args=(self.interface, bpf_filter), daemon=True)
        self.capture_thread.start()

        # Launch telemetry aggregator
        self.stats_thread = threading.Thread(target=self._stats_aggregator_loop, daemon=True)
        self.stats_thread.start()

        logger.info(f"[MONITORING] Started live packet sniffing on interface {self.interface or 'default'}")
        return True

    def stop(self) -> None:
        """Gracefully stop packet monitoring."""
        if not self.is_running:
            return

        logger.info("[MONITORING] Stopping packet capture...")
        self._stop_event.set()
        self.is_running = False
        self.mode = "IDLE"

        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=1.0)

        # Notify dashboard
        ws_manager.broadcast_sync("MONITORING_STATUS_CHANGED", self.get_status())
        logger.info("[MONITORING] Packet capture stopped.")

    def reset_state(self) -> None:
        self.packets_captured = 0
        self.bytes_captured = 0
        self.protocol_counts.clear()
        self.talkers.clear()
        self.dest_ports.clear()
        self.recent_packet_times.clear()
        self.history_samples.clear()
        self.port_scan_detector.reset()
        self.syn_flood_detector.reset()
        self.flow_aggregator.reset()
        self.error_message = None

    def _live_capture_loop(self, interface: Optional[str], bpf_filter: str):
        def _packet_callback(pkt):
            if self._stop_event.is_set():
                return
            try:
                self.packet_queue.put_nowait(pkt)
            except queue.Full:
                # Queue is bounded to prevent unbounded memory growth under huge spikes
                pass

        try:
            kwargs = {
                "prn": _packet_callback,
                "store": False,
                "stop_filter": lambda _: self._stop_event.is_set()
            }
            if interface:
                kwargs["iface"] = interface

            try:
                sniff(filter=bpf_filter or None, **kwargs)
            except Scapy_Exception as exc:
                if bpf_filter and "filter" in str(exc).lower():
                    logger.warning("[MONITORING] BPF filter failed (libpcap issue), retrying without filter")
                    sniff(**kwargs)
                else:
                    raise
        except Exception as e:
            self.error_message = f"Live packet capture failed: {str(e)}"
            logger.error(f"[MONITORING] Error in live capture loop: {e}")
            self.is_running = False
            self.mode = "IDLE"

    def _pcap_reader_loop(self, pcap_path: str):
        try:
            with PcapReader(pcap_path) as reader:
                for pkt in reader:
                    if self._stop_event.is_set():
                        break
                    try:
                        self.packet_queue.put(pkt, timeout=0.1)
                    except queue.Full:
                        pass
            logger.info(f"[MONITORING] Finished reading PCAP file: {pcap_path}")
        except Exception as e:
            self.error_message = f"PCAP reading failed: {str(e)}"
            logger.error(f"[MONITORING] Error in PCAP reader: {e}")

    def _worker_loop(self):
        """Worker thread that continuously pulls packets from the queue and feeds detection engines."""
        packet_count_since_prune = 0

        while not self._stop_event.is_set() or not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                parsed = PacketParser.parse(pkt)
                if not parsed:
                    continue

                ts = parsed["timestamp"]
                pkt_len = parsed["length"]

                self.packets_captured += 1
                self.bytes_captured += pkt_len
                proto = parsed["protocol"]
                self.protocol_counts[proto] += 1

                src_ip = parsed.get("src_ip")
                dst_ip = parsed.get("dst_ip")
                if src_ip:
                    self.talkers[src_ip] += 1
                dst_port = parsed.get("dst_port")
                if dst_port and dst_port < 49152:
                    self.dest_ports[f"{dst_port}/{proto.lower()}"] += 1

                # Sliding rate window
                self.recent_packet_times.append((ts, pkt_len))

                # 1. Port scan detector
                if proto == "TCP" and src_ip and dst_ip and dst_port:
                    ps_alert = self.port_scan_detector.process_packet(
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        is_syn_attempt=parsed["is_syn_attempt"]
                    )
                    if ps_alert:
                        event_service.handle_detected_threat(ps_alert)

                # 2. SYN flood detector
                if proto == "TCP" and src_ip and dst_ip and dst_port:
                    syn_alert = self.syn_flood_detector.process_packet(
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        is_syn=parsed["is_syn"],
                        is_ack=parsed["is_ack"]
                    )
                    if syn_alert:
                        event_service.handle_detected_threat(syn_alert)

                # 3. Flow aggregator for ML
                flow_features = self.flow_aggregator.process_packet(parsed)

                # Prune old state periodically
                packet_count_since_prune += 1
                if packet_count_since_prune >= 2000:
                    self.port_scan_detector.prune(ts)
                    self.syn_flood_detector.prune(ts)
                    self.flow_aggregator.prune(ts)
                    packet_count_since_prune = 0

            except Exception as e:
                logger.debug(f"[MONITORING] Packet processing error: {e}")

    def _stats_aggregator_loop(self):
        """Periodically aggregates PPS/BPS and publishes to WebSocket & DB."""
        while not self._stop_event.is_set():
            time.sleep(1.0)
            now_ts = time.time()

            # Clean expired rate elements older than 1.0 second
            while self.recent_packet_times and (now_ts - self.recent_packet_times[0][0]) > 1.0:
                self.recent_packet_times.popleft()

            current_pps = len(self.recent_packet_times)
            current_bps = sum(p[1] for p in self.recent_packet_times)

            stat_sample = {
                "timestamp": datetime.utcnow().isoformat(),
                "pps": current_pps,
                "bps": current_bps,
                "active_flows": self.flow_aggregator.active_flow_count
            }
            self.history_samples.append(stat_sample)

            # Persist summary statistic record every 5 seconds or when traffic exists
            if current_pps > 0 or len(self.history_samples) % 5 == 0:
                db = SessionLocal()
                try:
                    stat_record = NetworkStatistic(
                        timestamp=datetime.utcnow(),
                        packets_per_second=float(current_pps),
                        bytes_per_second=float(current_bps),
                        tcp_packets=self.protocol_counts["TCP"],
                        udp_packets=self.protocol_counts["UDP"],
                        icmp_packets=self.protocol_counts["ICMP"],
                        active_flows=self.flow_aggregator.active_flow_count
                    )
                    db.add(stat_record)
                    db.commit()
                finally:
                    db.close()

            # Broadcast to WebSocket
            ws_manager.broadcast_sync("TRAFFIC_STATS_UPDATE", {
                "current_pps": current_pps,
                "current_bps": current_bps,
                "total_packets": self.packets_captured,
                "total_bytes": self.bytes_captured,
                "protocols": dict(self.protocol_counts),
                "top_talkers": [{"ip": k, "count": v} for k, v in self.talkers.most_common(5)],
                "top_ports": [{"port": k, "count": v} for k, v in self.dest_ports.most_common(5)],
                "history": list(self.history_samples)
            })

    def get_status(self) -> Dict[str, Any]:
        uptime = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time and self.is_running else 0.0
        return {
            "is_running": self.is_running,
            "mode": self.mode,
            "interface": self.interface,
            "packets_captured": self.packets_captured,
            "bytes_captured": self.bytes_captured,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime_seconds": round(uptime, 1),
            "available_interfaces": self.get_available_interfaces(),
            "has_capture_permissions": True,
            "error_message": self.error_message
        }

    def get_statistics(self) -> Dict[str, Any]:
        current_pps = len(self.recent_packet_times)
        current_bps = sum(p[1] for p in self.recent_packet_times)
        return {
            "current_pps": current_pps,
            "current_bps": current_bps,
            "total_packets": self.packets_captured,
            "total_bytes": self.bytes_captured,
            "tcp_packets": self.protocol_counts["TCP"],
            "udp_packets": self.protocol_counts["UDP"],
            "icmp_packets": self.protocol_counts["ICMP"],
            "other_packets": self.protocol_counts["Other IPv4"] + self.protocol_counts["Non-IPv4"],
            "top_talkers": [{"ip": k, "count": v} for k, v in self.talkers.most_common(5)],
            "top_ports": [{"port": k, "count": v} for k, v in self.dest_ports.most_common(5)],
            "history": list(self.history_samples)
        }


sniffer_service = NetworkSnifferService()
