import {
  SecurityEvent,
  EventStatistics,
  MonitoringStatus,
  NetworkStatistics,
  PreventionStatus,
  BlockedAddress,
  MLMetrics,
  SystemStatus,
  PreventionMode
} from '../types';

const API_BASE = '/api';

export async function fetchHealth(): Promise<{ status: string; database_connected: boolean }> {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchSystemStatus(): Promise<SystemStatus> {
  const res = await fetch(`${API_BASE}/system/status`);
  return res.json();
}

export async function fetchMonitoringStatus(): Promise<MonitoringStatus> {
  const res = await fetch(`${API_BASE}/monitoring/status`);
  return res.json();
}

export async function startMonitoring(params: { interface?: string; pcap_path?: string; bpf_filter?: string }): Promise<any> {
  const res = await fetch(`${API_BASE}/monitoring/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to start monitoring');
  }
  return res.json();
}

export async function stopMonitoring(): Promise<any> {
  const res = await fetch(`${API_BASE}/monitoring/stop`, { method: 'POST' });
  return res.json();
}

export async function fetchNetworkStatistics(): Promise<NetworkStatistics> {
  const res = await fetch(`${API_BASE}/monitoring/statistics`);
  return res.json();
}

export async function fetchEvents(params?: {
  attack_type?: string;
  severity?: string;
  source_ip?: string;
  limit?: number;
  offset?: number;
}): Promise<SecurityEvent[]> {
  const query = new URLSearchParams();
  if (params?.attack_type) query.append('attack_type', params.attack_type);
  if (params?.severity) query.append('severity', params.severity);
  if (params?.source_ip) query.append('source_ip', params.source_ip);
  if (params?.limit) query.append('limit', params.limit.toString());
  if (params?.offset) query.append('offset', params.offset.toString());

  const res = await fetch(`${API_BASE}/events?${query.toString()}`);
  return res.json();
}

export async function fetchEventStatistics(): Promise<EventStatistics> {
  const res = await fetch(`${API_BASE}/events/statistics`);
  return res.json();
}

export async function fetchEventById(id: string): Promise<SecurityEvent> {
  const res = await fetch(`${API_BASE}/events/${id}`);
  if (!res.ok) throw new Error('Event not found');
  return res.json();
}

export async function fetchPreventionStatus(): Promise<PreventionStatus> {
  const res = await fetch(`${API_BASE}/prevention/status`);
  return res.json();
}

export async function fetchBlockedIPs(): Promise<BlockedAddress[]> {
  const res = await fetch(`${API_BASE}/prevention/blocked-ips`);
  return res.json();
}

export async function blockIP(ip_address: string, reason: string, duration_seconds: number = 300): Promise<any> {
  const res = await fetch(`${API_BASE}/prevention/block-ip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip_address, reason, duration_seconds })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to block IP');
  }
  return res.json();
}

export async function unblockIP(ip_address: string, reason: string = 'Manual unblock'): Promise<any> {
  const res = await fetch(`${API_BASE}/prevention/unblock-ip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip_address, reason })
  });
  return res.json();
}

export async function setPreventionMode(mode: PreventionMode): Promise<any> {
  const res = await fetch(`${API_BASE}/prevention/mode`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode })
  });
  return res.json();
}

export async function fetchMLMetrics(): Promise<MLMetrics> {
  const res = await fetch(`${API_BASE}/ml/metrics`);
  return res.json();
}

export async function simulateAuthAttempt(username: string, password: string): Promise<{ success: boolean; message: string; is_locked: boolean }> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  return res.json();
}

export async function fetchSimulationStatus(): Promise<any> {
  const res = await fetch(`${API_BASE}/simulation/status`);
  return res.json();
}

export async function startAttackSimulation(params: {
  attack_type: string;
  source_ip?: string;
  target_ip?: string;
  target_port?: number;
  intensity?: string;
  auto_enforce?: boolean;
}): Promise<any> {
  const res = await fetch(`${API_BASE}/simulation/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to start attack simulation');
  }
  return res.json();
}

export async function stopAttackSimulation(): Promise<any> {
  const res = await fetch(`${API_BASE}/simulation/stop`, { method: 'POST' });
  return res.json();
}
