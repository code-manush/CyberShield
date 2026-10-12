import React, { useState } from 'react';
import {
  Lock,
  Unlock,
  ShieldCheck,
  AlertTriangle,
  Clock,
  CheckCircle,
  PlusCircle,
  Info
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

export const PreventionPage: React.FC<PreventionPageProps> = ({
  status,
  blockedIPs,
  onModeChange,
  onBlockIP,
  onUnblockIP,
  onRefresh
}) => {
  const [showBlockModal, setShowBlockModal] = useState<boolean>(false);
  const [inputIP, setInputIP] = useState<string>('');
  const [inputReason, setInputReason] = useState<string>('');
  const [inputDuration, setInputDuration] = useState<number>(300);
  const [actionError, setActionError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  const handleModeSelect = async (mode: PreventionMode) => {
    try {
      setLoading(true);
      await onModeChange(mode);
    } catch (e: any) {
      setActionError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleBlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputIP.trim()) return;
    try {
      setLoading(true);
      setActionError(null);
      await onBlockIP(inputIP.trim(), inputReason.trim() || 'Manual administrative block', inputDuration);
      setShowBlockModal(false);
      setInputIP('');
      setInputReason('');
    } catch (e: any) {
      setActionError(e.message || 'Failed to block IP');
    } finally {
      setLoading(false);
    }
  };

  const handleUnblock = async (ip: string) => {
    try {
      setLoading(true);
      await onUnblockIP(ip);
    } catch (e: any) {
      setActionError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Response Mode Selector Card */}
      <div className="card">
        <div className="card-title">
          <Lock size={16} color="var(--accent-cyan)" />
          <span>Defensive Response Policy Mode</span>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
          Configures automated responses to detected threats. Switch between passive observation, alert routing, and active IP blocking.
        </p>

        {actionError && (
          <div style={{
            padding: '10px 14px',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '6px',
            color: '#fca5a5',
            fontSize: '0.85rem',
            marginBottom: '16px'
          }}>
            {actionError}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          {/* OBSERVE */}
          <div
            onClick={() => handleModeSelect('OBSERVE')}
            style={{
              padding: '18px',
              borderRadius: '8px',
              border: `2px solid ${status?.mode === 'OBSERVE' ? 'var(--accent-cyan)' : 'var(--border-color)'}`,
              background: status?.mode === 'OBSERVE' ? 'rgba(56, 189, 248, 0.08)' : 'var(--bg-tertiary)',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontWeight: 700, fontSize: '0.95rem', color: '#f8fafc' }}>Mode A: OBSERVE</span>
              {status?.mode === 'OBSERVE' && <CheckCircle size={18} color="var(--accent-cyan)" />}
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Passive telemetry logging. Events are recorded and displayed on the dashboard without altering host firewall state. Default safe mode.
            </p>
          </div>

          {/* ALERT */}
          <div
            onClick={() => handleModeSelect('ALERT')}
            style={{
              padding: '18px',
              borderRadius: '8px',
              border: `2px solid ${status?.mode === 'ALERT' ? '#f97316' : 'var(--border-color)'}`,
              background: status?.mode === 'ALERT' ? 'rgba(249, 115, 22, 0.08)' : 'var(--bg-tertiary)',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontWeight: 700, fontSize: '0.95rem', color: '#fdba74' }}>Mode B: ALERT</span>
              {status?.mode === 'ALERT' && <CheckCircle size={18} color="#f97316" />}
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Real-time threat notification. Events trigger high-priority alerts across WebSocket channels. No automated blocking.
            </p>
          </div>

          {/* ENFORCE */}
          <div
            onClick={() => handleModeSelect('ENFORCE')}
            style={{
              padding: '18px',
              borderRadius: '8px',
              border: `2px solid ${status?.mode === 'ENFORCE' ? '#ef4444' : 'var(--border-color)'}`,
              background: status?.mode === 'ENFORCE' ? 'rgba(239, 68, 68, 0.08)' : 'var(--bg-tertiary)',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontWeight: 700, fontSize: '0.95rem', color: '#fca5a5' }}>Mode C: ENFORCE</span>
              {status?.mode === 'ENFORCE' && <CheckCircle size={18} color="#ef4444" />}
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Active defensive mitigation. Offending IPs exceeding critical risk thresholds are isolated using reversible leases.
            </p>
          </div>
        </div>
      </div>

      {/* Adapter Info & Trusted Allowlist */}
      <div className="grid-2">
        <div className="card">
          <div className="card-title">
            <Info size={16} color="var(--accent-cyan)" />
            <span>Firewall Adapter Status</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Active Adapter Engine:</span>
              <span style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{status?.adapter}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Default Lease Duration:</span>
              <span className="mono" style={{ fontWeight: 600 }}>{status?.default_block_duration_seconds} seconds</span>
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {status?.adapter === 'SimulationFirewallAdapter' ? (
                <span>
                  <strong>Simulation Mode Active:</strong> Defenses are modeled statefully in memory and persistent storage without modifying host firewall rules. Blocks are clearly demarcated as <code>SIMULATION</code>.
                </span>
              ) : (
                <span>
                  <strong>Native Firewall Integration Active:</strong> Rules are dynamically added to iptables with scoped comments and expiration hooks.
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <ShieldCheck size={16} color="#34d399" />
            <span>Trusted IP Allowlist</span>
          </div>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
            The following addresses are strictly protected by allowlist verification and will never be blocked automatically:
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {status?.trusted_ips.map((ip) => (
              <span key={ip} className="mono" style={{
                padding: '4px 10px',
                background: 'var(--bg-tertiary)',
                borderRadius: '4px',
                fontSize: '0.8rem',
                border: '1px solid var(--border-color)',
                color: '#34d399'
              }}>
                {ip}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Blocked IPs Table Card */}
      <div className="card">
        <div className="card-title" style={{ justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={16} color="#f87171" />
            <span>Blocked IP Address Management ({blockedIPs.length} Records)</span>
          </div>
          <button onClick={() => setShowBlockModal(true)} className="btn btn-primary btn-sm">
            <PlusCircle size={14} />
            <span>Manual IP Block</span>
          </button>
        </div>

        <div className="table-container" style={{ marginTop: '14px' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>Target IP</th>
                <th>Reason</th>
                <th>Enacted Time</th>
                <th>Lease Expiration</th>
                <th>Status</th>
                <th>Action Mode</th>
                <th>Operation</th>
              </tr>
            </thead>
            <tbody>
              {blockedIPs.map((blk) => (
                <tr key={blk.id}>
                  <td className="mono" style={{ fontWeight: 600, color: '#f87171' }}>
                    {blk.ip_address}
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {blk.reason}
                  </td>
                  <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {new Date(blk.created_at).toLocaleTimeString()}
                  </td>
                  <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {blk.expires_at ? new Date(blk.expires_at).toLocaleTimeString() : 'Permanent'}
                  </td>
                  <td>
                    <span className={`badge ${blk.status === 'ACTIVE' ? 'badge-critical' : 'badge-low'}`}>
                      {blk.status}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {blk.action_mode}
                    </span>
                  </td>
                  <td>
                    {blk.status === 'ACTIVE' ? (
                      <button
                        onClick={() => handleUnblock(blk.ip_address)}
                        className="btn btn-secondary btn-sm"
                        style={{ gap: '4px' }}
                      >
                        <Unlock size={12} />
                        <span>Unblock</span>
                      </button>
                    ) : (
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Resolved</span>
                    )}
                  </td>
                </tr>
              ))}
              {blockedIPs.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                    No IP addresses are currently blocked.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual Block Modal */}
      {showBlockModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100
        }}>
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-color)',
            borderRadius: '10px',
            padding: '24px',
            width: '420px',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)'
          }}>
            <h3 style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Lock size={18} color="var(--accent-cyan)" />
              <span>Enact Manual IP Block</span>
            </h3>

            <form onSubmit={handleBlockSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  IP Address to Block
                </label>
                <input
                  type="text"
                  placeholder="e.g. 198.51.100.45"
                  value={inputIP}
                  onChange={(e) => setInputIP(e.target.value)}
                  required
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-primary)',
                    fontFamily: 'var(--font-mono)'
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  Block Reason / Justification
                </label>
                <input
                  type="text"
                  placeholder="e.g. Suspicious unauthorized probing"
                  value={inputReason}
                  onChange={(e) => setInputReason(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-primary)'
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  Lease Duration (Seconds)
                </label>
                <input
                  type="number"
                  value={inputDuration}
                  onChange={(e) => setInputDuration(Number(e.target.value))}
                  min={10}
                  max={86400}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-primary)'
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button
                  type="button"
                  onClick={() => setShowBlockModal(false)}
                  className="btn btn-secondary btn-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="btn btn-primary btn-sm"
                >
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
