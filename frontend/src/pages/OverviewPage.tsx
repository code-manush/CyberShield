import React from 'react';
import {
  ShieldAlert,
  Radio,
  Flame,
  KeyRound,
  ArrowUpRight,
  TrendingUp,
  Activity
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { SecurityEvent, EventStatistics, NetworkStatistics, PreventionStatus } from '../types';

interface OverviewPageProps {
  stats: EventStatistics | null;
  netStats: NetworkStatistics | null;
  prevStatus: PreventionStatus | null;
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
  onNavigateTab: (tab: string) => void;
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#f43f5e',
  HIGH:     '#fb923c',
  MEDIUM:   '#fbbf24',
  LOW:      '#60a5fa',
  INFO:     '#34d399'
};

const PIE_COLORS = ['#6366f1', '#22d3ee', '#a78bfa', '#fb923c', '#34d399'];

const TOOLTIP_STYLE = {
  contentStyle: {
    background: '#1e2330',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: 10,
    fontSize: 12,
    boxShadow: '0 8px 24px rgba(0,0,0,0.5)'
  },
  labelStyle: { color: '#8b95a6' }
};

export const OverviewPage: React.FC<OverviewPageProps> = ({
  stats,
  netStats,
  prevStatus,
  events,
  onSelectEvent,
  onNavigateTab
}) => {
  const severityData = stats
    ? Object.entries(stats.severity_distribution).map(([sev, count]) => ({
        severity: sev,
        count,
        color: SEV_COLORS[sev] || '#545d6d'
      }))
    : [];

  const attackData = stats
    ? Object.entries(stats.attack_distribution).map(([name, value]) => ({
        name: name.replace('_SUSPECTED', '').replace(/_/g, ' '),
        value
      }))
    : [];

  const trafficHistory = netStats?.history && netStats.history.length > 0
    ? netStats.history.map((h, i) => ({ time: `${i}s`, pps: h.pps, bps: Math.round(h.bps / 1024) }))
    : [{ time: '0s', pps: 0, bps: 0 }];

  const metricCards = [
    {
      label: 'Total Threats',
      value: stats?.total_events ?? 0,
      sub: 'Security detections',
      icon: ShieldAlert,
      color: '#6366f1',
      bg: 'rgba(99,102,241,0.12)'
    },
    {
      label: 'Port Scans',
      value: stats?.port_scan_count ?? 0,
      sub: 'TCP sweep events',
      icon: Radio,
      color: '#22d3ee',
      bg: 'rgba(34,211,238,0.12)'
    },
    {
      label: 'SYN Floods',
      value: stats?.syn_flood_count ?? 0,
      sub: 'High-rate SYN bursts',
      icon: Flame,
      color: '#fb923c',
      bg: 'rgba(251,146,60,0.12)'
    },
    {
      label: 'Brute Force',
      value: stats?.brute_force_count ?? 0,
      sub: 'Credential attacks',
      icon: KeyRound,
      color: '#a78bfa',
      bg: 'rgba(167,139,250,0.12)'
    }
  ];

  return (
    <div className="stack fade-in">
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-desc">Real-time threat summary across all detection engines</p>
        </div>
        <button
          onClick={() => onNavigateTab('threats')}
          className="btn btn-secondary btn-sm"
        >
          View All Threats
          <ArrowUpRight size={13} />
        </button>
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
              <div className="metric-card-value" style={{ color: m.color }}>
                {m.value}
              </div>
              <div className="metric-card-label">{m.label}</div>
              <div className="metric-card-sub">{m.sub}</div>
            </div>
          );
        })}
      </div>

      {/* Charts row */}
      <div className="grid-2">
        {/* Traffic chart */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={15} color="var(--indigo-l)" />
              Network Traffic Rate
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {netStats?.current_pps ?? 0} pkts/s &middot; {((netStats?.current_bps ?? 0) / 1024).toFixed(1)} KB/s
            </span>
          </div>
          <div style={{ height: 200 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficHistory}>
                <defs>
                  <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#6366f1" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#545d6d" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#545d6d" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Area
                  type="monotone"
                  dataKey="pps"
                  stroke="#6366f1"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#ppsGrad)"
                  name="Packets/sec"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack distribution */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <TrendingUp size={15} color="var(--sev-high)" />
              Attack Distribution
            </div>
          </div>
          <div style={{ height: 200, display: 'flex', alignItems: 'center' }}>
            {attackData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={attackData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={75}
                    innerRadius={45}
                    paddingAngle={3}
                  >
                    {attackData.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip {...TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', width: '100%', color: 'var(--text-muted)', fontSize: 13, lineHeight: 1.6 }}>
                No attacks detected yet.<br />
                <span style={{ fontSize: 12 }}>Run a simulation or replay a capture to see data.</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Severity + Defense status */}
      <div className="grid-2">
        {/* Severity chart */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Severity Breakdown</div>
          </div>
          <div style={{ height: 200 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} barCategoryGap="35%">
                <XAxis dataKey="severity" stroke="#545d6d" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#545d6d" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Defense status */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Active Defense</div>
            <span style={{
              padding: '3px 10px',
              borderRadius: 99,
              fontSize: 11,
              fontWeight: 700,
              background: prevStatus?.mode === 'ENFORCE' ? 'rgba(244,63,94,0.15)' : 'rgba(99,102,241,0.15)',
              color: prevStatus?.mode === 'ENFORCE' ? '#fb7185' : 'var(--indigo-l)',
              border: `1px solid ${prevStatus?.mode === 'ENFORCE' ? 'rgba(244,63,94,0.3)' : 'rgba(99,102,241,0.3)'}`
            }}>
              {prevStatus?.mode ?? 'OBSERVE'}
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              { label: 'Blocked Addresses', sub: 'Lease-controlled IPs', value: prevStatus?.active_blocks_count ?? 0, color: '#f43f5e' },
              { label: 'Firewall Adapter', sub: 'Execution layer', value: prevStatus?.adapter ?? 'Simulation', color: 'var(--cyan)' },
              { label: 'Trusted Allowlist', sub: 'Always exempt', value: `${prevStatus?.trusted_ips?.length ?? 0} IPs`, color: 'var(--emerald)' }
            ].map((row) => (
              <div
                key={row.label}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '10px 14px',
                  background: 'var(--bg-elevated)',
                  borderRadius: 8,
                  border: '1px solid var(--border-subtle)'
                }}
              >
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{row.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>{row.sub}</div>
                </div>
                <div style={{ fontWeight: 700, color: row.color, fontSize: 15 }}>{row.value}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent detections */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <ShieldAlert size={15} color="var(--indigo-l)" />
            Recent Detections
          </div>
          <button onClick={() => onNavigateTab('threats')} className="btn btn-ghost btn-sm">
            View all <ArrowUpRight size={12} />
          </button>
        </div>

        <div className="table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Attack Type</th>
                <th>Source IP</th>
                <th>Target</th>
                <th>Risk</th>
                <th>Severity</th>
                <th>Action</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 8).map((ev) => (
                <tr key={ev.id}>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td style={{ fontWeight: 600, fontSize: 12 }}>{ev.attack_type.replace(/_/g, ' ')}</td>
                  <td className="mono" style={{ color: 'var(--cyan)', fontSize: 12 }}>{ev.source_ip}</td>
                  <td className="mono" style={{ color: 'var(--text-secondary)', fontSize: 11 }}>
                    {ev.destination_ip
                      ? `${ev.destination_ip}${ev.destination_port ? `:${ev.destination_port}` : ''}`
                      : '—'}
                  </td>
                  <td>
                    <span style={{
                      fontWeight: 700,
                      fontSize: 13,
                      color: ev.risk_score >= 70 ? 'var(--sev-critical)' : ev.risk_score >= 40 ? 'var(--sev-medium)' : 'var(--sev-info)'
                    }}>
                      {ev.risk_score.toFixed(0)}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${ev.severity.toLowerCase()}`}>
                      {ev.severity}
                    </span>
                  </td>
                  <td style={{ fontSize: 11, color: ev.action_taken.includes('BLOCK') ? '#fb7185' : 'var(--text-muted)', fontWeight: 600 }}>
                    {ev.action_taken}
                  </td>
                  <td>
                    <button onClick={() => onSelectEvent(ev)} className="btn btn-ghost btn-xs">
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                    No events recorded. The system is operating normally.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
