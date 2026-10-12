export type AttackType = 
  | 'PORT_SCAN' 
  | 'SYN_FLOOD_SUSPECTED' 
  | 'HIGH_SYN_RATE' 
  | 'POSSIBLE_DISTRIBUTED_FLOOD' 
  | 'BRUTE_FORCE_SUSPECTED' 
  | 'ML_ANOMALY';

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type PreventionMode = 'OBSERVE' | 'ALERT' | 'ENFORCE';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  attack_type: string;
  source_ip: string;
  destination_ip?: string | null;
  destination_port?: number | null;
  severity: Severity;
  risk_score: number;
  detection_method: string;
  evidence_json: string;
  evidence?: Record<string, any>;
  action_taken: string;
  status: string;
}

export interface EventStatistics {
  total_events: number;
  port_scan_count: number;
  syn_flood_count: number;
  brute_force_count: number;
  severity_distribution: Record<string, number>;
  attack_distribution: Record<string, number>;
  recent_events_timeline: Array<{
    id: string;
    timestamp: string;
    attack_type: string;
    severity: string;
    risk_score: number;
    source_ip: string;
  }>;
}

export interface MonitoringStatus {
  is_running: boolean;
  mode: 'IDLE' | 'LIVE_CAPTURE' | 'PCAP_REPLAY';
  interface?: string | null;
  packets_captured: number;
  bytes_captured: number;
  start_time?: string | null;
  uptime_seconds: number;
  available_interfaces: string[];
  has_capture_permissions: boolean;
  error_message?: string | null;
}

export interface NetworkStatistics {
  current_pps: number;
  current_bps: number;
  total_packets: number;
  total_bytes: number;
  tcp_packets: number;
  udp_packets: number;
  icmp_packets: number;
  other_packets: number;
  top_talkers: Array<{ ip: string; count: number }>;
  top_ports: Array<{ port: string; count: number }>;
  history: Array<{
    timestamp: string;
    pps: number;
    bps: number;
    active_flows: number;
  }>;
}

export interface BlockedAddress {
  id: string;
  ip_address: string;
  reason: string;
  created_at: string;
  expires_at?: string | null;
  status: 'ACTIVE' | 'EXPIRED' | 'UNBLOCKED';
  action_mode: 'SIMULATION' | 'ENFORCE_IPTABLES';
}

export interface PreventionStatus {
  mode: PreventionMode;
  adapter: string;
  active_blocks_count: number;
  trusted_ips: string[];
  default_block_duration_seconds: number;
  dry_run_mode: boolean;
}

export interface MLMetrics {
  is_trained: boolean;
  model_type: string;
  model_version: string;
  dataset_source: string;
  training_set_size: number;
  test_set_size: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  confusion_matrix: number[][];
  classes: string[];
  features: string[];
  per_class_metrics: Record<string, {
    precision: number;
    recall: number;
    f1_score: number;
    support: number;
  }>;
  baseline_comparison: {
    baseline_type: string;
    baseline_accuracy: number;
    baseline_f1_score: number;
    ml_f1_improvement: number;
  };
  feature_importances: Record<string, number>;
  trained_at?: string;
}

export interface SystemStatus {
  system: {
    os: string;
    os_release: string;
    python_version: string;
    server_start_time: string;
    uptime_seconds: number;
  };
  monitoring: {
    is_running: boolean;
    mode: string;
    interface?: string | null;
  };
  prevention: {
    mode: string;
    adapter: string;
  };
  machine_learning: {
    is_trained: boolean;
    model_type: string;
  };
}
