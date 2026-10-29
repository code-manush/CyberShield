import React, { useState } from 'react';
import {
  Lock,
  Unlock,
  ShieldCheck,
  AlertTriangle,
  Server,
  PlusCircle,
  CheckCircle2,
  X,
  Eye,
  Zap,
  Shield
} from 'lucide-react';
import { PreventionStatus, BlockedAddress, PreventionMode } from '../types';

interface PreventionPageProps {
  status: PreventionStatus | null;
  blockedIPs: BlockedAddress[];
  onModeChange: (mode: PreventionMode) => Promise<void>;
  onBlockIP: (ip: string, reason: string, duration: number) => Promise<void>;
  onUnblockIP: (ip: string) => Promise<void>;
  onRefresh: () => void;
}

const MODES: Array<{
  id: PreventionMode;
  label: string;
  desc: string;
  icon: React.ElementType;
  color: string;
  bg: string;
  border: string;
}> = [
  {
    id: 'OBSERVE',
    label: 'Observe',
    desc: 'Passive logging. Threats are recorded and displayed. No firewall modifications.',
    icon: Eye,
    color: 'var(--emerald)',
    bg: 'rgba(16,185,129,0.08)',
    border: 'rgba(16,185,129,0.4)'
  },
  {
    id: 'ALERT',
    label: 'Alert',
    desc: 'Real-time notifications. High-priority alerts are pushed to WebSocket clients. No blocking.',
    icon: Zap,
    color: 'var(--sev-medium)',
    bg: 'rgba(251,191,36,0.08)',
    border: 'rgba(251,191,36,0.4)'
  },
  {
    id: 'ENFORCE',
    label: 'Enforce',
    desc: 'Active mitigation. High-risk IPs are automatically isolated via lease-based blocks.',
    icon: Shield,
    color: 'var(--sev-critical)',
    bg: 'rgba(244,63,94,0.08)',
    border: 'rgba(244,63,94,0.4)'
  }
];

export const PreventionPage: React.FC<PreventionPageProps> = ({
  status,
  blockedIPs,
  onModeChange,
  onBlockIP,
  onUnblockIP,
  onRefresh
}) => {
  const [showModal, setShowModal]       = useState(false);
  const [inputIP, setInputIP]           = useState('');
  const [inputReason, setInputReason]   = useState('');
  const [inputDuration, setInputDuration] = useState(300);
  const [actionError, setActionError]   = useState<string | null>(null);
  const [loading, setLoading]           = useState(false);

  const run = async (fn: () => Promise<void>) => {
    try { setLoading(true); setActionError(null); await fn(); }
    catch (e: any) { setActionError(e.message || 'Action failed'); }
    finally { setLoading(false); }
  };

  const handleBlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputIP.trim()) return;
    await run(() => onBlockIP(inputIP.trim(), inputReason.trim() || 'Manual administrative block', inputDuration));
    if (!actionError) { setShowModal(false); setInputIP(''); setInputReason(''); }
  };

  return (
    <div className="stack fade-in">
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Prevention Center</h1>
          <p className="page-desc">Configure defensive response policy and manage blocked addresses</p>
        </div>
        <button onClick={() => setShowModal(true)} className="btn btn-primary btn-sm">
          <PlusCircle size={13} /> Manual Block
        </button>
      </div>

      {actionError && (
        <div className="banner banner-danger">
          <AlertTriangle size={14} />
          {actionError}
        </div>
      )}

      {/* Mode selector */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Lock size={15} color="var(--indigo-l)" />
            Response Policy Mode
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Click to switch mode</span>
        </div>
        <div className="grid-3">
          {MODES.map((m) => {
            const Icon = m.icon;
            const isActive = status?.mode === m.id;
            return (
              <div
                key={m.id}
                id={`mode-${m.id.toLowerCase()}`}
                onClick={() => run(() => onModeChange(m.id))}
                style={{
                  padding: '18px 20px',
                  borderRadius: 12,
                  border: `1.5px solid ${isActive ? m.border : 'var(--border-subtle)'}`,
                  background: isActive ? m.bg : 'var(--bg-elevated)',
                  cursor: 'pointer',
                  transition: 'all 0.18s ease',
                  position: 'relative',
                  overflow: 'hidden'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                  <div style={{
                    width: 36,
                    height: 36,
                    borderRadius: 8,
                    background: isActive ? `${m.bg}` : 'var(--bg-overlay)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <Icon size={17} color={isActive ? m.color : 'var(--text-muted)'} />
                  </div>
                  {isActive && <CheckCircle2 size={16} color={m.color} />}
                </div>
                <div style={{ fontWeight: 700, fontSize: 14, color: isActive ? m.color : 'var(--text-primary)', marginBottom: 4 }}>
                  {m.label}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {m.desc}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Firewall info + Trusted IPs */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Server size={15} color="var(--indigo-l)" />
              Firewall Adapter
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              { label: 'Active Engine', value: status?.adapter ?? '—', color: 'var(--cyan)' },
              { label: 'Default Lease', value: `${status?.default_block_duration_seconds ?? 0}s`, color: 'var(--text-primary)' }
            ].map((row) => (
              <div key={row.label} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '10px 14px',
                background: 'var(--bg-elevated)',
                borderRadius: 8,
                border: '1px solid var(--border-subtle)'
              }}>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{row.label}</span>
                <span className="mono" style={{ fontWeight: 600, color: row.color, fontSize: 12 }}>{row.value}</span>
              </div>
            ))}
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.6 }}>
              {status?.adapter === 'SimulationFirewallAdapter'
                ? '⚠ Simulation mode active — blocks are stored in memory only, no host firewall rules modified.'
                : '✓ Native iptables integration active — rules applied with scoped comments and expiration.'}
            </p>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <ShieldCheck size={15} color="var(--emerald)" />
              Trusted Allowlist
            </div>
            <span className="badge badge-info">{status?.trusted_ips?.length ?? 0} IPs</span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12, lineHeight: 1.6 }}>
            These addresses are permanently protected and will never be auto-blocked:
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {status?.trusted_ips?.map((ip) => (
              <span key={ip} className="mono badge badge-neutral" style={{ fontSize: 11, color: 'var(--emerald)' }}>
                {ip}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Blocked IPs table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={15} color="var(--sev-high)" />
            <span style={{ fontWeight: 600, fontSize: 13 }}>Blocked Addresses</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{blockedIPs.length} records</span>
          </div>
        </div>

        <div className="table-container" style={{ border: 'none', borderRadius: 0 }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Blocked At</th>
                <th>Expires</th>
                <th>Status</th>
                <th>Mode</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {blockedIPs.map((blk) => (
                <tr key={blk.id}>
                  <td className="mono" style={{ fontWeight: 700, color: '#fb7185', fontSize: 12 }}>
                    {blk.ip_address}
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)', maxWidth: 200 }}>
                    {blk.reason}
                  </td>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {new Date(blk.created_at).toLocaleTimeString()}
                  </td>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {blk.expires_at ? new Date(blk.expires_at).toLocaleTimeString() : 'Permanent'}
                  </td>
                  <td>
                    <span className={`badge badge-${blk.status === 'ACTIVE' ? 'critical' : 'neutral'}`}>
                      {blk.status}
                    </span>
                  </td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{blk.action_mode}</td>
                  <td>
                    {blk.status === 'ACTIVE' ? (
                      <button
                        onClick={() => run(() => onUnblockIP(blk.ip_address))}
                        className="btn btn-ghost btn-xs"
                        disabled={loading}
                      >
                        <Unlock size={12} /> Unblock
                      </button>
                    ) : (
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Expired</span>
                    )}
                  </td>
                </tr>
              ))}
              {blockedIPs.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                    No IP addresses are currently blocked.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual block modal */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">
              <Lock size={16} color="var(--indigo-l)" />
              Manual IP Block
              <button
                onClick={() => setShowModal(false)}
                className="btn btn-ghost btn-xs"
                style={{ marginLeft: 'auto', padding: '4px 6px' }}
              >
                <X size={14} />
              </button>
            </div>

            <form onSubmit={handleBlockSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label className="label">IP Address</label>
                <input
                  id="block-ip-input"
                  type="text"
                  className="input input-mono"
                  placeholder="e.g. 192.168.1.100"
                  value={inputIP}
                  onChange={(e) => setInputIP(e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="label">Reason</label>
                <input
                  id="block-reason-input"
                  type="text"
                  className="input"
                  placeholder="e.g. Suspicious port scanning"
                  value={inputReason}
                  onChange={(e) => setInputReason(e.target.value)}
                />
              </div>
              <div>
                <label className="label">Duration (seconds)</label>
                <input
                  id="block-duration-input"
                  type="number"
                  className="input"
                  value={inputDuration}
                  onChange={(e) => setInputDuration(Number(e.target.value))}
                  min={10}
                  max={86400}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 4 }}>
                <button type="button" onClick={() => setShowModal(false)} className="btn btn-secondary btn-sm">
                  Cancel
                </button>
                <button type="submit" disabled={loading} className="btn btn-primary btn-sm">
                  Confirm Block
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
