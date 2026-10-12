from typing import Optional, Dict, Any
from scapy.all import IP, TCP, UDP, ICMP


class PacketParser:
    """Extracts normalized packet telemetry from raw Scapy packets."""

    TCP_SYN = 0x02
    TCP_ACK = 0x10
    TCP_FIN = 0x01
    TCP_RST = 0x04
    TCP_PSH = 0x08
    TCP_URG = 0x20

    @staticmethod
    def parse(pkt: Any) -> Optional[Dict[str, Any]]:
        """Parse packet into a normalized dictionary representation.
        
        Extracts only essential header fields; full raw payloads are omitted by default.
        """
        try:
            ts = float(pkt.time)
        except Exception:
            return None

        pkt_len = len(pkt)
        if IP not in pkt:
            return {
                "timestamp": ts,
                "length": pkt_len,
                "protocol": "Non-IPv4",
                "src_ip": None,
                "dst_ip": None
            }

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        parsed = {
            "timestamp": ts,
            "length": pkt_len,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ttl": ip_layer.ttl,
            "protocol": "Other IPv4",
            "src_port": None,
            "dst_port": None,
            "is_syn_attempt": False,
            "is_syn": False,
            "is_ack": False,
            "is_fin": False,
            "is_rst": False,
            "tcp_flags": None,
            "icmp_type": None
        }

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            flags = int(tcp_layer.flags)
            parsed["protocol"] = "TCP"
            parsed["src_port"] = tcp_layer.sport
            parsed["dst_port"] = tcp_layer.dport
            parsed["tcp_flags"] = flags
            parsed["is_syn"] = bool(flags & PacketParser.TCP_SYN)
            parsed["is_ack"] = bool(flags & PacketParser.TCP_ACK)
            parsed["is_fin"] = bool(flags & PacketParser.TCP_FIN)
            parsed["is_rst"] = bool(flags & PacketParser.TCP_RST)
            # A connection attempt is SYN set and ACK clear
            parsed["is_syn_attempt"] = bool(parsed["is_syn"] and not parsed["is_ack"])

        elif UDP in pkt:
            udp_layer = pkt[UDP]
            parsed["protocol"] = "UDP"
            parsed["src_port"] = udp_layer.sport
            parsed["dst_port"] = udp_layer.dport

        elif ICMP in pkt:
            icmp_layer = pkt[ICMP]
            parsed["protocol"] = "ICMP"
            parsed["icmp_type"] = icmp_layer.type

        return parsed
