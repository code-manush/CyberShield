import React, { useState, useEffect } from 'react';
import {
  Crosshair,
  Flame,
  ShieldAlert,
  ShieldCheck,
  Play,
  Square,
  Terminal,
  Activity,
  Lock,
  ArrowRight,
  Zap,
  Info,
  CheckCircle2,
  AlertOctagon
} from 'lucide-react';
import { AttackSimulationStatus, PreventionMode } from '../types';

interface AttackLabPageProps {
  simStatus: AttackSimulationStatus | null;
  preventionMode: PreventionMode;
  onStartAttack: (attackType: string, autoEnforce: boolean) => Promise<void>;
  onStopAttack: () => Promise<void>;
  onNavigateTab: (tab: string) => void;
}

export const AttackLabPage: React.FC<AttackLabPageProps> = ({
  simStatus,
  preventionMode,
  onStartAttack,
  onStopAttack,
  onNavigateTab
}) => {
  const [autoEnforce, setAutoEnforce] = useState<boolean>(true);
  const [activeButton, setActiveButton] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const isAttacking = simStatus?.is_attacking ?? false;

  const handleLaunch = async (attackType: string) => {
    try {
      setErrorMsg(null);
      setActiveButton(attackType);
      await onStartAttack(attackType, autoEnforce);
    } catch (e: any) {
      setErrorMsg(e.message || 'Failed to start simulation');
    } finally {
      setActiveButton(null);
    }
  };

  const handleStop = async () => {
    try {
      await onStopAttack();
    } catch (e: any) {
      setErrorMsg(e.message);
    }
  };

  return (
    <div className="stack fade-in">
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Attack Lab</h1>
          <p className="page-desc">Simulate live multi-vector cyberattacks and observe real-time detection &amp; mitigation</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className={`badge ${isAttacking ? 'badge-critical' : 'badge-neutral'}`} style={{ fontSize: 12, padding: '5px 12px' }}>
            <div className={isAttacking ? 'pulse-dot-red' : 'pulse-dot'} />
            {isAttacking ? `ATTACKING: ${simStatus?.attack_type}` : 'STANDBY'}
          </span>
          {isAttacking && (
            <button className="btn btn-danger btn-sm" onClick={handleStop}>
              <Square size={13} /> Halt Attack
            </button>
          )}
        </div>
      </div>

      {/* Hero Mission Control Card */}
      <div className={`card ${isAttacking ? 'attacking' : ''}`}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <div style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: 'rgba(244,63,94,0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: '1px solid rgba(244,63,94,0.3)'
              }}>
                <Flame size={18} color="var(--sev-critical)" />
              </div>
              <h2 style={{ fontSize: 17, fontWeight: 700, letterSpacing: '-0.01em' }}>
                CyberAttack Simulation & Live Detection Lab
              </h2>
            </div>
            <p className="helper-text" style={{ maxWidth: '850px' }}>
              Simulate live, multi-vector cyberattacks against CyberShield in real time. Packets and auth attempts are paced dynamically so you can observe the rate meters pulse, detection engines flag alerts, and the firewall enforce automated IP bans.
            </p>
          </div>

          <div />
        </div>

        {/* Live Attack Progress HUD */}
        {isAttacking && (
          <div style={{ marginTop: 20, padding: 16, background: 'rgba(6,9,15,0.8)', borderRadius: 10, border: '1px solid rgba(244,63,94,0.3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '0.85rem' }}>
              <span style={{ color: '#fca5a5', fontWeight: 600 }}>{simStatus?.current_step}</span>
              <span className="mono" style={{ color: 'var(--text-muted)' }}>
                {simStatus?.packets_sent} / {simStatus?.total_packets} packets ({simStatus?.progress_percent}%)
              </span>
            </div>
            <div className="progress-bar-container">
              <div className="progress-bar-fill" style={{ width: `${simStatus?.progress_percent ?? 0}%` }} />
            </div>
          </div>
        )}

        {/* Settings Bar */}
        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', fontSize: 13 }}>
            <input
              type="checkbox"
              checked={autoEnforce}
              onChange={(e) => setAutoEnforce(e.target.checked)}
              style={{ width: 15, height: 15, accentColor: 'var(--indigo)' }}
            />
            <span style={{ fontWeight: 600 }}>Auto-Enable ENFORCE Mode</span>
            <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>Automatically blocks attacker IP during demo</span>
          </label>

          <div style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', gap: 16 }}>
            <span>Defense: <strong style={{ color: preventionMode === 'ENFORCE' ? 'var(--sev-critical)' : 'var(--indigo-l)' }}>{preventionMode}</strong></span>
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="banner banner-danger">{errorMsg}</div>
      )}

      {/* 4 Interactive Attack Cards */}
      <div className="grid-2">
        {/* Vector 1: Port Scan */}
        <div className="attack-card">
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Crosshair size={20} color="var(--cyan)" />
              </div>
              <span className="badge badge-indigo">RECONNAISSANCE</span>
            </div>

            <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 6 }}>
              1. Port Scan Attack
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.6 }}>
              Simulates a threat actor probing 24 service ports (SSH, HTTP, MySQL, RDP) from IP <code className="mono">198.51.100.42</code>. Tests the sliding window rule engine.
            </p>

            <div style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '10px 12px', borderRadius: 8, marginBottom: 12, lineHeight: 1.7, border: '1px solid var(--border-subtle)' }}>
              <div>• Attacker IP: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>198.51.100.42</strong></div>
              <div>• Probed Ports: <strong>21, 22, 25, 80, 443, 3306, 8080… (24 ports)</strong></div>
              <div>• Threshold: <strong>≥15 ports in 10s</strong></div>
            </div>
          </div>

          <button
            className="btn btn-primary"
            disabled={isAttacking}
            onClick={() => handleLaunch('PORT_SCAN')}
          >
            <Play size={16} />
            <span>Launch Port Scan Attack</span>
          </button>
        </div>

        {/* Vector 2: SYN Flood */}
        <div className="attack-card">
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(244,63,94,0.12)', border: '1px solid rgba(244,63,94,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Activity size={20} color="var(--sev-critical)" />
              </div>
              <span className="badge badge-critical">DoS</span>
            </div>

            <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 6 }}>
              2. TCP SYN Flood (DoS)
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.6 }}>
              Bombards target port 80 with a high-rate burst of 140 half-open TCP SYN handshakes from IP <code className="mono">203.0.113.88</code>. Watch the throughput graph jump to 65+ pkts/s and trigger a Critical alert!
            </p>

            <div style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '10px 12px', borderRadius: 8, marginBottom: 12, lineHeight: 1.7, border: '1px solid var(--border-subtle)' }}>
              <div>• Attacker IP: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>203.0.113.88</strong></div>
              <div>• Burst: <strong>140 SYN Packets (~65 pkts/s)</strong></div>
              <div>• Threshold: <strong>≥100 SYNs in 5s</strong></div>
            </div>
          </div>

          <button
            className="btn btn-primary"
            style={{ background: 'rgba(244,63,94,0.15)', color: '#fb7185', border: '1px solid rgba(244,63,94,0.3)' }}
            disabled={isAttacking}
            onClick={() => handleLaunch('SYN_FLOOD')}
          >
            <Play size={16} />
            <span>Launch SYN Flood Burst</span>
          </button>
        </div>

        {/* Vector 3: Brute Force */}
        <div className="attack-card">
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(251,191,36,0.12)', border: '1px solid rgba(251,191,36,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Lock size={20} color="var(--sev-medium)" />
              </div>
              <span className="badge badge-medium">CREDENTIAL</span>
            </div>

            <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 6 }}>
              3. Brute-Force Password Spray
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.6 }}>
              Fires 15 rapid unauthorized login attempts using a common dictionary against the <code className="mono">admin</code> account from IP <code className="mono">198.51.100.99</code>. Triggers lockout and security notification without password leakage.
            </p>

            <div style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '10px 12px', borderRadius: 8, marginBottom: 12, lineHeight: 1.7, border: '1px solid var(--border-subtle)' }}>
              <div>• Target: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>admin</strong></div>
              <div>• Offending IP: <strong style={{ fontFamily: 'var(--font-mono)' }}>198.51.100.99</strong></div>
              <div>• Threshold: <strong>≥10 failures in 60s</strong></div>
            </div>
          </div>

          <button
            className="btn btn-primary"
            style={{ background: 'rgba(251,191,36,0.12)', color: '#fde68a', border: '1px solid rgba(251,191,36,0.3)' }}
            disabled={isAttacking}
            onClick={() => handleLaunch('BRUTE_FORCE')}
          >
            <Play size={16} />
            <span>Launch Brute Force Attack</span>
          </button>
        </div>

        {/* Vector 4: Multi-Vector Kill-Chain */}
        <div className="attack-card" style={{ borderColor: 'rgba(167,139,250,0.3)', background: 'rgba(167,139,250,0.04)' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(167,139,250,0.12)', border: '1px solid rgba(167,139,250,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Zap size={20} color="var(--violet)" />
              </div>
              <span className="badge" style={{ background: 'rgba(167,139,250,0.15)', color: '#c4b5fd', border: '1px solid rgba(167,139,250,0.35)' }}>
                FULL KILL-CHAIN
              </span>
            </div>

            <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 6 }}>
              4. Multi-Vector Kill-Chain
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.6 }}>
              Executes all 3 attack stages sequentially: Reconnaissance (Port Scan) ➡️ Infiltration (Brute-Force) ➡️ Denial of Service (SYN Flood). Demonstrates CyberShield detecting multiple vectors simultaneously.
            </p>

            <div style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '10px 12px', borderRadius: 8, marginBottom: 12, lineHeight: 1.7, border: '1px solid var(--border-subtle)' }}>
              <div>• Phase 1: <strong>Reconnaissance (16 ports sweep)</strong></div>
              <div>• Phase 2: <strong>Credential stuffing (12 auth attempts)</strong></div>
              <div>• Phase 3: <strong>SYN flood exhaustion (100 packets)</strong></div>
            </div>
          </div>

          <button
            className="btn btn-primary"
            style={{ background: 'rgba(167,139,250,0.15)', color: '#c4b5fd', border: '1px solid rgba(167,139,250,0.35)' }}
            disabled={isAttacking}
            onClick={() => handleLaunch('MULTI_VECTOR')}
          >
            <Zap size={16} />
            <span>Launch Full Kill-Chain Assault</span>
          </button>
        </div>
      </div>

      {/* Live Terminal Output & Post-Attack Actions */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div className="card-title">
            <Terminal size={15} color="var(--cyan)" />
            <span>Simulation Console</span>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-ghost btn-sm" onClick={() => onNavigateTab('threats')}>
              <ShieldAlert size={13} /> Threats
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => onNavigateTab('prevention')}>
              <ShieldCheck size={13} /> Prevention
            </button>
          </div>
        </div>

        <div className="terminal-box">
          {simStatus?.logs && simStatus.logs.length > 0 ? (
            simStatus.logs.map((line, idx) => {
              const isAlert = line.includes('THREAT') || line.includes('BLOCKED') || line.includes('⚠️');
              const isSuccess = line.includes('complete') || line.includes('ENFORCE') || line.includes('===');
              return (
                <div
                  key={idx}
                  className={`terminal-line ${isAlert ? 'terminal-line-alert' : isSuccess ? 'terminal-line-success' : ''}`}
                >
                  {line}
                </div>
              );
            })
          ) : (
            <div style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
              Console standing by. Choose an attack vector above and click "Launch" to start streaming packets live...
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
