import React from 'react';
import {
  Wifi,
  WifiOff,
  Shield,
  Play,
  Square,
  RefreshCw,
  GraduationCap,
  FlaskConical,
  ChevronDown
} from 'lucide-react';
import { PreventionMode } from '../types';

interface HeaderProps {
  isWsConnected: boolean;
  monitoringMode: string;
  isMonitoring: boolean;
  preventionMode: PreventionMode;
  onToggleMonitoring: () => void;
  onRefresh: () => void;
  onOpenGuide: () => void;
  onNavigateTab: (tab: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  isWsConnected,
  monitoringMode,
  isMonitoring,
  preventionMode,
  onToggleMonitoring,
  onRefresh,
  onOpenGuide,
  onNavigateTab
}) => {
  const modeColor: Record<string, string> = {
    ENFORCE: 'var(--sev-critical)',
    ALERT:   'var(--sev-high)',
    OBSERVE: 'var(--emerald)'
  };

  const modeBg: Record<string, string> = {
    ENFORCE: 'rgba(244,63,94,0.12)',
    ALERT:   'rgba(251,146,60,0.12)',
    OBSERVE: 'rgba(16,185,129,0.12)'
  };

  const modeBorder: Record<string, string> = {
    ENFORCE: 'rgba(244,63,94,0.3)',
    ALERT:   'rgba(251,146,60,0.3)',
    OBSERVE: 'rgba(16,185,129,0.3)'
  };

  const color  = modeColor[preventionMode]  ?? 'var(--indigo-l)';
  const bg     = modeBg[preventionMode]     ?? 'rgba(99,102,241,0.12)';
  const border = modeBorder[preventionMode] ?? 'rgba(99,102,241,0.3)';

  return (
    <header className="header">
      {/* Left: status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
        {/* WS connection */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {isWsConnected ? (
            <>
              <Wifi size={14} color="var(--emerald)" />
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--emerald)', letterSpacing: '0.04em' }}>LIVE</span>
            </>
          ) : (
            <>
              <WifiOff size={14} color="var(--sev-critical)" />
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--sev-critical)', letterSpacing: '0.04em' }}>OFFLINE</span>
            </>
          )}
        </div>

        <div style={{ height: 16, width: 1, background: 'var(--border-subtle)' }} />

        {/* Capture status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
          <span style={{ color: 'var(--text-muted)' }}>Capture</span>
          <span style={{
            padding: '2px 8px',
            borderRadius: 99,
            fontWeight: 700,
            fontSize: 11,
            background: isMonitoring ? 'rgba(99,102,241,0.15)' : 'var(--bg-elevated)',
            color: isMonitoring ? 'var(--indigo-l)' : 'var(--text-muted)',
            border: `1px solid ${isMonitoring ? 'rgba(99,102,241,0.35)' : 'var(--border-subtle)'}`,
            letterSpacing: '0.04em'
          }}>
            {monitoringMode}
          </span>
        </div>

        <div style={{ height: 16, width: 1, background: 'var(--border-subtle)' }} />

        {/* Defense mode */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
          <Shield size={13} color={color} />
          <span style={{ color: 'var(--text-muted)' }}>Defense</span>
          <span style={{
            padding: '2px 8px',
            borderRadius: 99,
            fontWeight: 700,
            fontSize: 11,
            background: bg,
            color,
            border: `1px solid ${border}`,
            letterSpacing: '0.04em'
          }}>
            {preventionMode}
          </span>
        </div>
      </div>

      {/* Right: actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button
          id="btn-guide"
          onClick={onOpenGuide}
          className="btn btn-ghost btn-sm"
          title="Open Presentation Guide"
        >
          <GraduationCap size={14} />
          <span>Guide</span>
        </button>

        <button
          id="btn-attack-lab"
          onClick={() => onNavigateTab('attack-lab')}
          className="btn btn-sm"
          style={{
            background: 'rgba(244,63,94,0.12)',
            color: '#fb7185',
            border: '1px solid rgba(244,63,94,0.3)',
          }}
          title="Open Attack Lab"
        >
          <FlaskConical size={14} />
          <span>Attack Lab</span>
        </button>

        <div style={{ height: 16, width: 1, background: 'var(--border-subtle)' }} />

        <button
          id="btn-toggle-monitor"
          onClick={onToggleMonitoring}
          className={`btn btn-sm ${isMonitoring ? 'btn-danger' : 'btn-secondary'}`}
          title={isMonitoring ? 'Stop Packet Capture' : 'Start Live Sniffer'}
        >
          {isMonitoring ? <Square size={13} /> : <Play size={13} />}
          <span>{isMonitoring ? 'Stop' : 'Start Sniffer'}</span>
        </button>

        <button
          id="btn-refresh"
          onClick={onRefresh}
          className="btn btn-ghost btn-sm"
          title="Refresh Data"
          style={{ padding: '6px 8px' }}
        >
          <RefreshCw size={14} />
        </button>
      </div>
    </header>
  );
};
