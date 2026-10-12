import React, { useState } from 'react';
import {
  Activity,
  Play,
  Square,
  FileCheck,
  AlertCircle,
  Network,
  Clock,
  HardDrive
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { MonitoringStatus, NetworkStatistics } from '../types';

interface LiveMonitoringPageProps {
  status: MonitoringStatus | null;
  netStats: NetworkStatistics | null;
  onStartCapture: (iface?: string) => Promise<void>;
  onStartPcap: (pcapPath: string) => Promise<void>;
  onStopCapture: () => Promise<void>;
}

const PROTO_COLORS = ['#38bdf8', '#818cf8', '#34d399', '#f43f5e'];

export const LiveMonitoringPage: React.FC<LiveMonitoringPageProps> = ({
  status,
  netStats,
  onStartCapture,
  onStartPcap,
  onStopCapture
}) => {
  const [selectedIface, setSelectedIface] = useState<string>('');
  const [pcapPath, setPcapPath] = useState<string>('sample_traffic.pcap');
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleStartLive = async () => {
    try {
      setLoading(true);
      setErrorMsg(null);
      await onStartCapture(selectedIface || undefined);
    } catch (e: any) {
      setErrorMsg(e.message || 'Failed to start live capture');
    } finally {
      setLoading(false);
    }
  };

  const handleStartPcapReplay = async () => {
    try {
      setLoading(true);
      setErrorMsg(null);
      await onStartPcap(pcapPath);
    } catch (e: any) {
      setErrorMsg(e.message || 'Failed to start PCAP replay');
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    try {
      setLoading(true);
      await onStopCapture();
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  const protoData = netStats ? [
    { name: 'TCP', value: netStats.tcp_packets },
    { name: 'UDP', value: netStats.udp_packets },
    { name: 'ICMP', value: netStats.icmp_packets },
    { name: 'Other', value: netStats.other_packets }
  ].filter(p => p.value > 0) : [];

  const historyData = netStats?.history && netStats.history.length > 0
    ? netStats.history.map((h, i) => ({
        time: `${i}s`,
        pps: h.pps,
        kbps: Math.round(h.bps / 1024)
      }))
    : [{ time: '0s', pps: 0, kbps: 0 }];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Controls & Configuration Card */}
      <div className="card">
        <div className="card-title">
          <Activity size={16} color="var(--accent-cyan)" />
          <span>Packet Sniffer Operations & Capture Controls</span>
        </div>

        {errorMsg && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 14px',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '6px',
            color: '#fca5a5',
            fontSize: '0.85rem',
            marginBottom: '16px'
          }}>
            <AlertCircle size={16} />
            <span>{errorMsg}</span>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginTop: '12px' }}>
          {/* Live Interface Selection */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px' }}>
            <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Network size={16} color="var(--accent-cyan)" />
              <span>Live Network Interface</span>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
              Capture raw packets directly from an active adapter (requires admin / Npcap on Windows).
            </p>
            <div style={{ display: 'flex', gap: '10px' }}>
              <select
                value={selectedIface}
                onChange={(e) => setSelectedIface(e.target.value)}
                disabled={status?.is_running}
                style={{
                  flex: 1,
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-primary)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '0.85rem'
                }}
              >
                <option value="">Default OS Interface</option>
                {status?.available_interfaces.map((iface) => (
                  <option key={iface} value={iface}>{iface}</option>
                ))}
              </select>
              {status?.is_running && status.mode === 'LIVE_CAPTURE' ? (
                <button onClick={handleStop} disabled={loading} className="btn btn-danger">
                  <Square size={14} />
                  <span>Stop</span>
                </button>
              ) : (
                <button onClick={handleStartLive} disabled={loading || status?.is_running} className="btn btn-primary">
                  <Play size={14} />
                  <span>Start Live</span>
                </button>
              )}
            </div>
          </div>

          {/* Offline PCAP Replay */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px' }}>
            <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCheck size={16} color="#34d399" />
              <span>Offline PCAP Capture Analysis</span>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
              Reproducible forensic playback. Zero administrative privileges required.
            </p>
            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                type="text"
                value={pcapPath}
                onChange={(e) => setPcapPath(e.target.value)}
                placeholder="Path to .pcap or .pcapng file"
                disabled={status?.is_running}
                style={{
                  flex: 1,
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-primary)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontFamily: 'var(--font-mono)'
                }}
              />
              {status?.is_running && status.mode === 'PCAP_REPLAY' ? (
                <button onClick={handleStop} disabled={loading} className="btn btn-danger">
                  <Square size={14} />
                  <span>Stop</span>
                </button>
              ) : (
                <button onClick={handleStartPcapReplay} disabled={loading || status?.is_running} className="btn btn-secondary">
                  <Play size={14} />
                  <span>Analyze PCAP</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Telemetry Metrics */}
      <div className="grid-4">
        <div className="card">
          <div className="card-title">
            <Clock size={16} color="var(--accent-cyan)" />
            <span>Capture Uptime</span>
          </div>
          <div className="mono" style={{ fontSize: '1.75rem', fontWeight: 700 }}>
            {status?.uptime_seconds ? `${status.uptime_seconds.toFixed(0)}s` : '0s'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Mode: {status?.mode ?? 'IDLE'}
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Activity size={16} color="#38bdf8" />
            <span>Packet Rate</span>
          </div>
          <div className="mono" style={{ fontSize: '1.75rem', fontWeight: 700, color: '#38bdf8' }}>
            {netStats?.current_pps ?? 0} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>pkts/s</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Total Packets: {netStats?.total_packets ?? 0}
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <HardDrive size={16} color="#34d399" />
            <span>Data Volume Rate</span>
          </div>
          <div className="mono" style={{ fontSize: '1.75rem', fontWeight: 700, color: '#34d399' }}>
            {(((netStats?.current_bps ?? 0) / 1024)).toFixed(1)} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>KB/s</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Total: {(((netStats?.total_bytes ?? 0) / 1024)).toFixed(1)} KB
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Network size={16} color="#a855f7" />
            <span>Active TCP Flows</span>
          </div>
          <div className="mono" style={{ fontSize: '1.75rem', fontWeight: 700, color: '#a855f7' }}>
            {netStats?.history && netStats.history.length > 0 ? netStats.history[netStats.history.length - 1].active_flows : 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Bidirectional tracked sessions
          </div>
        </div>
      </div>

      {/* Visual Charts */}
      <div className="grid-2">
        <div className="card">
          <div className="card-title">
            <span>Throughput & Packet Rate Stream</span>
          </div>
          <div style={{ height: '240px', marginTop: '12px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={historyData}>
                <XAxis dataKey="time" stroke="#475569" fontSize={11} tickLine={false} />
                <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '6px' }}
                />
                <Line type="monotone" dataKey="pps" stroke="#38bdf8" strokeWidth={2} dot={false} name="Packets/s" />
                <Line type="monotone" dataKey="kbps" stroke="#34d399" strokeWidth={2} dot={false} name="KB/s" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <span>Protocol Distribution</span>
          </div>
          <div style={{ height: '240px', marginTop: '12px', display: 'flex', alignItems: 'center' }}>
            {protoData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protoData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={85}
                    innerRadius={50}
                    label={(e) => `${e.name}: ${e.value}`}
                  >
                    {protoData.map((_, i) => (
                      <Cell key={`proto-${i}`} fill={PROTO_COLORS[i % PROTO_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '6px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', width: '100%', color: 'var(--text-muted)' }}>
                No packets captured yet. Start live capture or run PCAP replay.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
