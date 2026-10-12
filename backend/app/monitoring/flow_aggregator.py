import time
import threading
from typing import Dict, Tuple, Optional, Any, List


class NetworkFlow:
    """Represents an active bidirectional network communication flow."""

    def __init__(self, key: Tuple[str, str, int, int, str], start_time: float):
        self.key = key  # (ip1, ip2, port1, port2, protocol)
        self.start_time = start_time
        self.last_seen = start_time
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.dst_port = key[3]

    def add_packet(self, ts: float, pkt_len: int, is_forward: bool, is_syn: bool, is_ack: bool, is_fin: bool, is_rst: bool):
        self.last_seen = max(self.last_seen, ts)
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len

        if is_syn:
            self.syn_count += 1
        if is_ack:
            self.ack_count += 1
        if is_fin:
            self.fin_count += 1
        if is_rst:
            self.rst_count += 1

    def to_feature_vector(self) -> Dict[str, Any]:
        """Convert accumulated flow statistics into a normalized feature dictionary."""
        duration = max(0.001, self.last_seen - self.start_time)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        syn_ratio = self.syn_count / max(1, total_packets)
        ack_ratio = self.ack_count / max(1, total_packets)
        bytes_per_sec = total_bytes / duration
        packets_per_sec = total_packets / duration
        is_well_known = 1 if (self.dst_port and self.dst_port < 1024) else 0

        return {
            "flow_duration": round(duration, 4),
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "total_fwd_bytes": self.fwd_bytes,
            "total_bwd_bytes": self.bwd_bytes,
            "flow_bytes_per_sec": round(bytes_per_sec, 2),
            "flow_packets_per_sec": round(packets_per_sec, 2),
            "syn_flag_count": self.syn_count,
            "ack_flag_count": self.ack_count,
            "syn_ratio": round(syn_ratio, 4),
            "ack_ratio": round(ack_ratio, 4),
            "destination_port": self.dst_port or 0,
            "is_well_known_port": is_well_known
        }


class FlowAggregator:
    """Manages active network flows and extracts feature representations."""

    def __init__(self, idle_timeout: float = 15.0):
        self.idle_timeout = idle_timeout
        self.flows: Dict[Tuple[str, str, int, int, str], NetworkFlow] = {}
        self._lock = threading.Lock()

    def _normalize_key(self, src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], proto: str) -> Tuple[Tuple[str, str, int, int, str], bool]:
        sport = src_port or 0
        dport = dst_port or 0
        if (src_ip, sport) <= (dst_ip, dport):
            return (src_ip, dst_ip, sport, dport, proto), True
        else:
            return (dst_ip, src_ip, dport, sport, proto), False

    def process_packet(self, parsed_pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update flow state with parsed packet. Returns flow features if flow is active."""
        src_ip = parsed_pkt.get("src_ip")
        dst_ip = parsed_pkt.get("dst_ip")
        proto = parsed_pkt.get("protocol")
        if not src_ip or not dst_ip:
            return None

        key, is_forward = self._normalize_key(
            src_ip, dst_ip,
            parsed_pkt.get("src_port"),
            parsed_pkt.get("dst_port"),
            proto
        )
        ts = parsed_pkt.get("timestamp", time.time())
        pkt_len = parsed_pkt.get("length", 64)

        with self._lock:
            if key not in self.flows:
                self.flows[key] = NetworkFlow(key, ts)

            flow = self.flows[key]
            flow.add_packet(
                ts=ts,
                pkt_len=pkt_len,
                is_forward=is_forward,
                is_syn=parsed_pkt.get("is_syn", False),
                is_ack=parsed_pkt.get("is_ack", False),
                is_fin=parsed_pkt.get("is_fin", False),
                is_rst=parsed_pkt.get("is_rst", False)
            )
            return flow.to_feature_vector()

    @property
    def active_flow_count(self) -> int:
        with self._lock:
            return len(self.flows)

    def prune(self, now: float) -> List[Dict[str, Any]]:
        """Remove flows that have been idle longer than idle_timeout."""
        expired_flows = []
        with self._lock:
            keys_to_del = []
            for k, f in self.flows.items():
                if (now - f.last_seen) > self.idle_timeout:
                    keys_to_del.append(k)
                    expired_flows.append(f.to_feature_vector())
            for k in keys_to_del:
                del self.flows[k]
        return expired_flows

    def reset(self) -> None:
        with self._lock:
            self.flows.clear()
