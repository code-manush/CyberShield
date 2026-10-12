import os
import random
import numpy as np
import pandas as pd
from typing import Tuple

FEATURE_COLUMNS = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "syn_flag_count",
    "ack_flag_count",
    "syn_ratio",
    "ack_ratio",
    "destination_port",
    "is_well_known_port"
]

TARGET_COLUMN = "label"
CLASSES = ["BENIGN", "PORT_SCAN", "SYN_FLOOD"]


def generate_synthetic_flow_dataset(
    n_samples: int = 6000,
    random_seed: int = 42,
    output_path: str = "datasets/network_flows.csv"
) -> pd.DataFrame:
    """Generate a realistic intrusion detection flow dataset modeled after CIC-IDS network distributions.
    
    Classes:
    - BENIGN: normal web (80, 443), DNS (53), DB queries with balanced bidirectional traffic, low SYN ratio, high ACK ratio.
    - PORT_SCAN: rapid single/few packet probes across diverse ports, zero/low backward packets, syn_flag_count=1, syn_ratio=1.0.
    - SYN_FLOOD: high volume of SYN packets to a single port (e.g. 80), zero backward packets, high packet rates, syn_ratio=1.0, ack_flag_count=0.
    """
    np.random.seed(random_seed)
    random.seed(random_seed)

    n_benign = int(n_samples * 0.50)      # 3000
    n_port_scan = int(n_samples * 0.25)   # 1500
    n_syn_flood = int(n_samples * 0.25)   # 1500

    data = []

    # --- 1. BENIGN FLOWS ---
    for _ in range(n_benign):
        duration = max(0.01, np.random.exponential(scale=2.5))
        fwd_pkts = np.random.randint(2, 35)
        bwd_pkts = np.random.randint(1, 40)
        fwd_bytes = fwd_pkts * np.random.randint(50, 800)
        bwd_bytes = bwd_pkts * np.random.randint(60, 1400)
        total_pkts = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes

        syn_count = 1 if np.random.random() < 0.95 else 0
        ack_count = total_pkts - syn_count

        dst_port = random.choice([80, 443, 53, 22, 3306, 5432, 8080])
        is_well_known = 1 if dst_port < 1024 else 0

        data.append({
            "flow_duration": duration,
            "total_fwd_packets": fwd_pkts,
            "total_bwd_packets": bwd_pkts,
            "total_fwd_bytes": fwd_bytes,
            "total_bwd_bytes": bwd_bytes,
            "flow_bytes_per_sec": total_bytes / duration,
            "flow_packets_per_sec": total_pkts / duration,
            "syn_flag_count": syn_count,
            "ack_flag_count": ack_count,
            "syn_ratio": syn_count / total_pkts,
            "ack_ratio": ack_count / total_pkts,
            "destination_port": dst_port,
            "is_well_known_port": is_well_known,
            "label": "BENIGN"
        })

    # --- 2. PORT SCAN FLOWS ---
    for _ in range(n_port_scan):
        duration = max(0.001, np.random.uniform(0.001, 0.2))  # very brief probe
        fwd_pkts = random.choice([1, 1, 1, 2])
        bwd_pkts = 0  # Unanswered connection probe
        fwd_bytes = fwd_pkts * random.choice([40, 60])
        bwd_bytes = 0
        total_pkts = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes

        syn_count = fwd_pkts
        ack_count = 0

        dst_port = np.random.randint(1, 65535)
        is_well_known = 1 if dst_port < 1024 else 0

        data.append({
            "flow_duration": duration,
            "total_fwd_packets": fwd_pkts,
            "total_bwd_packets": bwd_pkts,
            "total_fwd_bytes": fwd_bytes,
            "total_bwd_bytes": bwd_bytes,
            "flow_bytes_per_sec": total_bytes / duration,
            "flow_packets_per_sec": total_pkts / duration,
            "syn_flag_count": syn_count,
            "ack_flag_count": ack_count,
            "syn_ratio": 1.0,
            "ack_ratio": 0.0,
            "destination_port": dst_port,
            "is_well_known_port": is_well_known,
            "label": "PORT_SCAN"
        })

    # --- 3. SYN FLOOD FLOWS ---
    for _ in range(n_syn_flood):
        duration = max(0.05, np.random.uniform(0.1, 4.0))
        fwd_pkts = np.random.randint(50, 400)
        bwd_pkts = 0  # Target flooded, no 3-way handshake established
        fwd_bytes = fwd_pkts * 60
        bwd_bytes = 0
        total_pkts = fwd_pkts
        total_bytes = fwd_bytes

        syn_count = fwd_pkts
        ack_count = 0

        dst_port = random.choice([80, 443, 8080, 53])  # Target victim service
        is_well_known = 1 if dst_port < 1024 else 0

        data.append({
            "flow_duration": duration,
            "total_fwd_packets": fwd_pkts,
            "total_bwd_packets": bwd_pkts,
            "total_fwd_bytes": fwd_bytes,
            "total_bwd_bytes": bwd_bytes,
            "flow_bytes_per_sec": total_bytes / duration,
            "flow_packets_per_sec": total_pkts / duration,
            "syn_flag_count": syn_count,
            "ack_flag_count": ack_count,
            "syn_ratio": 1.0,
            "ack_ratio": 0.0,
            "destination_port": dst_port,
            "is_well_known_port": is_well_known,
            "label": "SYN_FLOOD"
        })

    df = pd.DataFrame(data)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    return df
