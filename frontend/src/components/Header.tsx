import React from 'react';
import { Wifi, WifiOff, Shield, Play, Square, RefreshCw } from 'lucide-react';
import { PreventionMode } from '../types';

interface HeaderProps {
  isWsConnected: boolean;
  monitoringMode: string;
  isMonitoring: boolean;
  preventionMode: PreventionMode;
  onToggleMonitoring: () => void;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  isWsConnected,
  monitoringMode,
  isMonitoring,
  preventionMode,
  onToggleMonitoring,
  onRefresh
}) => {
  const getModeBadgeClass = () => {
    switch (preventionMode) {
      case 'ENFORCE': return 'badge-critical';
      case 'ALERT': return 'badge-high';
      default: return 'badge-info';
    }
  };

  return (
    <header className="header">
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
          {isWsConnected ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#34d399', fontWeight: 600 }}>
              <Wifi size={16} />
              <span>LIVE TELEMETRY</span>
            </span>
          ) : (
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#f87171', fontWeight: 600 }}>
              <WifiOff size={16} />
              <span>RECONNECTING...</span>
            </span>
          )}
        </div>

        <div style={{ height: '18px', width: '1px', background: 'var(--border-color)' }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
          <span>Capture Status:</span>
          <span style={{
            padding: '2px 8px',
            borderRadius: '4px',
            fontWeight: 700,
            background: isMonitoring ? 'rgba(56, 189, 248, 0.15)' : 'rgba(100, 116, 139, 0.2)',
            color: isMonitoring ? 'var(--accent-cyan)' : 'var(--text-muted)',
            border: `1px solid ${isMonitoring ? 'rgba(56, 189, 248, 0.3)' : 'transparent'}`
          }}>
            {monitoringMode}
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
          <Shield size={16} color="var(--accent-cyan)" />
          <span>Defense Mode:</span>
          <span className={`badge ${getModeBadgeClass()}`}>
            {preventionMode}
          </span>
        </div>

        <button
          onClick={onToggleMonitoring}
          className={`btn btn-sm ${isMonitoring ? 'btn-danger' : 'btn-primary'}`}
          title={isMonitoring ? 'Stop Active Packet Capture' : 'Start Live Packet Sniffer'}
        >
          {isMonitoring ? <Square size={14} /> : <Play size={14} />}
          <span>{isMonitoring ? 'Stop Capture' : 'Start Sniffer'}</span>
        </button>

        <button onClick={onRefresh} className="btn btn-secondary btn-sm" title="Refresh Telemetry">
          <RefreshCw size={14} />
        </button>
      </div>
    </header>
  );
};
