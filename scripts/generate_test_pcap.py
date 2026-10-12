import os
import random
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap


def generate_test_pcap(output_path: str = "sample_traffic.pcap"):
    """Builds a deterministic test PCAP file containing background traffic and distinct attacks."""
    random.seed(42)
    start_ts = time.time() - 300  # 5 minutes ago
    packets = []

    def add(pkt, offset_sec):
        pkt.time = start_ts + offset_sec
        packets.append(pkt)

    def frame():
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

    print("[*] Generating benign background traffic (HTTPS, DNS, Ping)...")
    # 1. Normal traffic (should NOT trigger alerts)
    clients = [f"192.168.1.{i}" for i in range(100, 105)]
    servers = ["142.250.183.14", "13.107.42.14", "104.18.32.7"]

    for _ in range(500):
        t = random.uniform(0, 60)
        c, s = random.choice(clients), random.choice(servers)
        sport = random.randint(49152, 65535)
        roll = random.random()

        if roll < 0.2:  # New HTTPS connection (S)
            add(frame() / IP(src=c, dst=s) / TCP(sport=sport, dport=443, flags="S"), t)
        elif roll < 0.6:  # Data packet (PA)
            add(frame() / IP(src=c, dst=s) / TCP(sport=sport, dport=443, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n"), t)
        elif roll < 0.85:  # Server response (SA, PA)
            add(frame() / IP(src=s, dst=c) / TCP(sport=443, dport=sport, flags="PA") / Raw(b"HTTP/1.1 200 OK\r\n\r\n"), t)
        else:  # DNS Query
            add(frame() / IP(src=c, dst="8.8.8.8") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com")), t)

    # A few standard pings
    for i in range(5):
        add(frame() / IP(src="192.168.1.101", dst="8.8.8.8") / ICMP(type=8, id=1, seq=i), 5.0 + (i * 2.0))

    # 2. Attack 1: Port Scan (10.0.0.66 -> 192.168.1.10 across 30 ports)
    print("[*] Embedding Attack 1: Port Scan (30 distinct ports from 10.0.0.66)...")
    for i, dport in enumerate(range(20, 50)):
        add(frame() / IP(src="10.0.0.66", dst="192.168.1.10") / TCP(sport=50000 + i, dport=dport, flags="S"), 15.0 + (i * 0.05))

    # 3. Attack 2: TCP SYN Flood (150 SYN packets to 192.168.1.20:80)
    print("[*] Embedding Attack 2: TCP SYN Flood (150 packets to 192.168.1.20:80)...")
    for i in range(150):
        spoofed_src = f"172.16.0.{(i % 30) + 1}"
        add(frame() / IP(src=spoofed_src, dst="192.168.1.20") / TCP(sport=random.randint(1024, 65535), dport=80, flags="S"), 35.0 + (i * 0.015))

    packets.sort(key=lambda p: p.time)
    wrpcap(output_path, packets)
    print(f"[+] Wrote {len(packets)} packets to {output_path}")
    return output_path


if __name__ == "__main__":
    generate_test_pcap()
