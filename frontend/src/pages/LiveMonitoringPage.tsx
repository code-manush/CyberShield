import React, { useState } from 'react';
import {
  Activity,
  Play,
  Square,
  FileCheck,
  Network,
  Clock,
  HardDrive,
  Zap,
  AlertCircle,
  FlaskConical,
  Radio
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
  Cell,
  Legend
} from 'recharts';
import { MonitoringStatus, NetworkStatistics } from '../types';

interface LiveMonitoringPageProps {
  status: MonitoringStatus | null;
  netStats: NetworkStatistics | null;
  onStartCapture: (iface?: string) => Promise<void>;
  onStartPcap: (pcapPath: string) => Promise<void>;
  onStopCapture: () => Promise<void>;
  onNavigateTab?: (tab: string) => void;
}

const PROTO_COLORS = ['#6366f1', '#22d3ee', '#34d399', '#f43f5e'];

const TT = {
  contentStyle: {
    background: '#1e2330',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: 10,
    fontSize: 12,
    boxShadow: '0 8px 24px rgba(0,0,0,0.5)'
  },
  labelStyle: { color: '#8b95a6' }
};

export const LiveMonitoringPage: React.FC<LiveMonitoringPageProps> = ({
  status,
  netStats,
  onStartCapture,
  onStartPcap,
  onStopCapture,
  onNavigateTab
}) => {
  const [selectedIface, setSelectedIface] = useState('');
  const [pcapPath, setPcapPath]           = useState('sample_traffic.pcap');
  const [loading, setLoading]             = useState(false);
  const [errorMsg, setErrorMsg]           = useState<string | null>(null);

  const run = async (fn: () => Promise<void>) => {
    try { setLoading(true); setErrorMsg(null); await fn(); }
    catch (e: any) { setErrorMsg(e.message || 'Operation failed'); }
    finally { setLoading(false); }
  };

  const protoData = netStats ? [
    { name: 'TCP',   value: netStats.tcp_packets   },
    { name: 'UDP',   value: netStats.udp_packets   },
    { name: 'ICMP',  value: netStats.icmp_packets  },
    { name: 'Other', value: netStats.other_packets }
  ].filter(p => p.value > 0) : [];

  const historyData = netStats?.history?.length
    ? netStats.history.map((h, i) => ({ time: `${i}s`, pps: h.pps, kbps: Math.round(h.bps / 1024) }))
    : [{ time: '0s', pps: 0, kbps: 0 }];

  const currentPps   = netStats?.current_pps ?? 0;
  const totalPackets = netStats?.total_packets ?? 0;
  const isLive       = status?.is_running && status.mode === 'LIVE_CAPTURE';
  const isPcap       = status?.is_running && status.mode === 'PCAP_REPLAY';

  const metricCards = [
    {
      label: 'Uptime',
      value: status?.uptime_seconds ? `${status.uptime_seconds.toFixed(0)}s` : '0s',
      sub: `Mode: ${status?.mode ?? 'IDLE'}`,
      icon: Clock,
      color: '#6366f1',
      bg: 'rgba(99,102,241,0.12)'
    },
    {
      label: 'Packet Rate',
      value: `${currentPps}`,
      sub: `${totalPackets} total ingested`,
      icon: Activity,
      color: '#22d3ee',
      bg: 'rgba(34,211,238,0.12)',
      unit: 'pkts/s'
    },
    {
      label: 'Throughput',
      value: `${((netStats?.current_bps ?? 0) / 1024).toFixed(1)}`,
      sub: `${((netStats?.total_bytes ?? 0) / 1024).toFixed(1)} KB total`,
      icon: HardDrive,
      color: '#34d399',
      bg: 'rgba(52,211,153,0.12)',
      unit: 'KB/s'
    },
    {
      label: 'Active Flows',
      value: netStats?.history?.length
        ? netStats.history[netStats.history.length - 1].active_flows
        : 0,
      sub: 'TCP conversations',
      icon: Network,
      color: '#a78bfa',
      bg: 'rgba(167,139,250,0.12)'
    }
  ];

  return (
    <div className="stack fade-in">
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Live Monitoring</h1>
          <p className="page-desc">Packet capture, protocol analysis, and traffic telemetry</p>
        </div>
        {onNavigateTab && (
          <button
            onClick={() => onNavigateTab('attack-lab')}
            className="btn btn-sm"
            style={{ background: 'rgba(244,63,94,0.12)', color: '#fb7185', border: '1px solid rgba(244,63,94,0.3)' }}
          >
            <FlaskConical size={13} />
            Launch Attack Lab
          </button>
        )}
      </div>

      {/* Status banner */}
      <div className={`banner ${currentPps > 0 ? 'banner-success' : totalPackets > 0 ? 'banner-info' : 'banner-warn'}`}>
        {currentPps > 0
          ? <><span className="dot dot-green" />  <strong>Streaming</strong> — {currentPps} packets/sec in real-time</>
          : totalPackets > 0
          ? <><span className="dot dot-indigo" /> <strong>Analysis complete</strong> — {totalPackets} packets ingested. Network idle.</>
          : <><Zap size={14} />                    <strong>Idle</strong> — Start a capture or replay a PCAP to begin</>
        }
        <span style={{ fontSize: 12, marginLeft: 'auto', color: 'inherit', opacity: 0.7 }}>
          Start a test attack to see the charts light up!
        </span>
      </div>

      {/* Error */}
      {errorMsg && (
        <div className="banner banner-danger">
          <AlertCircle size={15} />
          {errorMsg}
        </div>
      )}

      {/* Capture controls */}
      <div className="grid-2">
        {/* PCAP replay */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <FileCheck size={15} color="var(--emerald)" />
              PCAP Replay
            </div>
            <span className="badge badge-info">No admin required</span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.6 }}>
            Stream a recorded network capture for offline analysis and detection testing.
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              id="pcap-path-input"
              type="text"
              value={pcapPath}
              onChange={(e) => setPcapPath(e.target.value)}
              placeholder="Path to .pcap file"
              disabled={status?.is_running}
              className="input input-mono"
              style={{ flex: 1 }}
            />
            {isPcap ? (
              <button onClick={() => run(onStopCapture)} disabled={loading} className="btn btn-danger">
                <Square size={13} /> Stop
              </button>
            ) : (
              <button
                id="btn-analyze-pcap"
                onClick={() => run(() => onStartPcap(pcapPath))}
                disabled={loading || status?.is_running}
                className="btn btn-primary"
              >
                <Play size={13} /> Analyze PCAP
              </button>
            )}
          </div>
        </div>

        {/* Live sniffing */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Radio size={15} color="var(--indigo-l)" />
              Live Network Interface
            </div>
            <span className="badge badge-neutral" style={{ fontSize: 10 }}>Requires Npcap on Windows</span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.6 }}>
            Sniff raw packets directly from a network adapter in real-time.
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <select
              id="interface-select"
              value={selectedIface}
              onChange={(e) => setSelectedIface(e.target.value)}
              disabled={status?.is_running}
              className="input"
              style={{ flex: 1 }}
            >
              <option value="">Default OS Interface</option>
              {status?.available_interfaces?.map((iface) => (
                <option key={iface} value={iface}>{iface}</option>
              ))}
            </select>
            {isLive ? (
              <button onClick={() => run(onStopCapture)} disabled={loading} className="btn btn-danger">
                <Square size={13} /> Stop
              </button>
            ) : (
              <button
                id="btn-start-live"
                onClick={() => run(() => onStartCapture(selectedIface || undefined))}
                disabled={loading || status?.is_running}
                className="btn btn-secondary"
              >
                <Play size={13} /> Start Live
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid-4">
        {metricCards.map((m) => {
          const Icon = m.icon;
          return (
            <div key={m.label} className="card metric-card">
              <div className="metric-card-icon" style={{ background: m.bg }}>
                <Icon size={18} color={m.color} />
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                <div className="metric-card-value mono" style={{ color: m.color }}>{m.value}</div>
                {(m as any).unit && <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{(m as any).unit}</span>}
              </div>
              <div className="metric-card-label">{m.label}</div>
              <div className="metric-card-sub">{m.sub}</div>
            </div>
          );
        })}
      </div>

      {/* Charts */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Traffic Stream</div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>pkts/s &amp; KB/s</span>
          </div>
          <div style={{ height: 220 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={historyData}>
                <XAxis dataKey="time" stroke="#545d6d" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#545d6d" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip {...TT} />
                <Line type="monotone" dataKey="pps"  stroke="#6366f1" strokeWidth={2.5} dot={false} name="Packets/s" />
                <Line type="monotone" dataKey="kbps" stroke="#34d399" strokeWidth={2}   dot={false} name="KB/s" />
                <Legend
                  wrapperStyle={{ fontSize: 11, paddingTop: 8, color: 'var(--text-secondary)' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Protocol Mix</div>
          </div>
          <div style={{ height: 220, display: 'flex', alignItems: 'center' }}>
            {protoData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protoData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={4}
                  >
                    {protoData.map((_, i) => (
                      <Cell key={i} fill={PROTO_COLORS[i % PROTO_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip {...TT} />
                  <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', width: '100%', color: 'var(--text-muted)', fontSize: 13 }}>
                No packets captured yet.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
