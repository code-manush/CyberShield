import React from 'react';
import {
  ShieldAlert,
  Radio,
  Lock,
  Layers,
  Flame,
  KeyRound,
  AlertTriangle,
  ArrowRight
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

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#10b981'
};

const PIE_COLORS = ['#38bdf8', '#f97316', '#a855f7', '#ec4899', '#10b981'];

export const OverviewPage: React.FC<OverviewPageProps> = ({
  stats,
  netStats,
  prevStatus,
  events,
  onSelectEvent,
  onNavigateTab
}) => {
  const severityData = stats ? Object.entries(stats.severity_distribution).map(([sev, count]) => ({
    severity: sev,
    count,
    color: SEVERITY_COLORS[sev] || '#64748b'
  })) : [];

  const attackData = stats ? Object.entries(stats.attack_distribution).map(([name, value]) => ({
    name: name.replace('_SUSPECTED', '').replace('_', ' '),
    value
  })) : [];

  const trafficHistory = netStats?.history && netStats.history.length > 0 
    ? netStats.history.map((h, i) => ({
        time: `${i}s`,
        pps: h.pps,
        bps: Math.round(h.bps / 1024) // KB/s
      }))
    : [{ time: '0s', pps: 0, bps: 0 }];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Metric Cards */}
      <div className="grid-4">
        <div className="card">
          <div className="card-title">
            <ShieldAlert size={16} color="var(--accent-cyan)" />
            <span>Total Threats</span>
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: '#f8fafc' }}>
            {stats?.total_events ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Cumulative security detections
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Radio size={16} color="#38bdf8" />
            <span>Port Scans</span>
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: '#38bdf8' }}>
            {stats?.port_scan_count ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            TCP horizontal / vertical sweeps
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Flame size={16} color="#f97316" />
            <span>SYN Floods</span>
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: '#f97316' }}>
            {stats?.syn_flood_count ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            High-rate unacknowledged SYNs
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <KeyRound size={16} color="#a855f7" />
            <span>Brute Force</span>
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: '#a855f7' }}>
            {stats?.brute_force_count ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Credential spray & brute force bursts
          </div>
        </div>
      </div>

      {/* Middle Row: Traffic Chart & Attack Distribution */}
      <div className="grid-2">
        <div className="card">
          <div className="card-title" style={{ justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={16} color="var(--accent-cyan)" />
              <span>Network Traffic Rate (Live Stream)</span>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Current: {netStats?.current_pps ?? 0} pkts/s ({((netStats?.current_bps ?? 0) / 1024).toFixed(1)} KB/s)
            </span>
          </div>
          <div style={{ height: '230px', marginTop: '12px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficHistory}>
                <defs>
                  <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={11} tickLine={false} />
                <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '6px' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Area type="monotone" dataKey="pps" stroke="#38bdf8" strokeWidth={2} fillOpacity={1} fill="url(#ppsGrad)" name="Packets/sec" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <AlertTriangle size={16} color="#f97316" />
            <span>Attack Category Breakdown</span>
          </div>
          <div style={{ height: '230px', marginTop: '12px', display: 'flex', alignItems: 'center' }}>
            {attackData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={attackData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    innerRadius={50}
                    label={(entry) => `${entry.name} (${entry.value})`}
                  >
                    {attackData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '6px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', width: '100%', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                No attacks detected yet. Run a test simulation or replay a capture to observe distribution.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Severity Distribution & Recent Alerts */}
      <div className="grid-2">
        <div className="card">
          <div className="card-title">
            <span>Threat Severity Distribution</span>
          </div>
          <div style={{ height: '220px', marginTop: '12px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <XAxis dataKey="severity" stroke="#475569" fontSize={11} tickLine={false} />
                <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '6px' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`sev-cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-title" style={{ justifyContent: 'space-between' }}>
            <span>Active Defensive Status</span>
            <span style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
              Mode: {prevStatus?.mode ?? 'OBSERVE'}
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <div>
                <div style={{ fontWeight: 600 }}>Active Blocked Addresses</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Lease-controlled source IPs</div>
              </div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f87171' }}>
                {prevStatus?.active_blocks_count ?? 0}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <div>
                <div style={{ fontWeight: 600 }}>Firewall Adapter Engine</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Defensive execution layer</div>
              </div>
              <div style={{ fontWeight: 600, color: '#38bdf8' }}>
                {prevStatus?.adapter ?? 'Simulation'}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <div>
                <div style={{ fontWeight: 600 }}>Trusted Allowlist Count</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Exempt from blocking</div>
              </div>
              <div style={{ fontWeight: 600, color: '#34d399' }}>
                {prevStatus?.trusted_ips?.length ?? 0} IPs
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Detections Table */}
      <div className="card">
        <div className="card-title" style={{ justifyContent: 'space-between' }}>
          <span>Recent Security Detections</span>
          <button onClick={() => onNavigateTab('threats')} className="btn btn-secondary btn-sm">
            <span>View All Threat Records</span>
            <ArrowRight size={14} />
          </button>
        </div>

        <div className="table-container" style={{ marginTop: '14px' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Attack Category</th>
                <th>Source IP</th>
                <th>Target</th>
                <th>Risk Score</th>
                <th>Severity</th>
                <th>Action Taken</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 7).map((ev) => (
                <tr key={ev.id}>
                  <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td style={{ fontWeight: 600 }}>{ev.attack_type}</td>
                  <td className="mono" style={{ color: 'var(--accent-cyan)' }}>{ev.source_ip}</td>
                  <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                    {ev.destination_ip ? `${ev.destination_ip}${ev.destination_port ? `:${ev.destination_port}` : ''}` : '-'}
                  </td>
                  <td>
                    <span style={{ fontWeight: 700, color: ev.risk_score >= 70 ? '#f87171' : '#fde047' }}>
                      {ev.risk_score.toFixed(1)}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${ev.severity.toLowerCase()}`}>
                      {ev.severity}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: ev.action_taken.includes('BLOCK') ? '#f87171' : 'var(--text-secondary)' }}>
                      {ev.action_taken}
                    </span>
                  </td>
                  <td>
                    <button onClick={() => onSelectEvent(ev)} className="btn btn-secondary btn-sm">
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                    No security events recorded. The system is operating normally.
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
