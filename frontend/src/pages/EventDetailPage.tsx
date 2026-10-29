import React from 'react';
import {
  ShieldAlert,
  ArrowLeft,
  Server,
  Activity,
  Code,
  CheckCircle,
  AlertTriangle
} from 'lucide-react';
import { SecurityEvent } from '../types';

interface EventDetailPageProps {
  event: SecurityEvent | null;
  onBack: () => void;
}

export const EventDetailPage: React.FC<EventDetailPageProps> = ({ event, onBack }) => {
  if (!event) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '48px' }}>
        <p style={{ color: 'var(--text-muted)' }}>No security event selected for deep inspection.</p>
        <button onClick={onBack} className="btn btn-secondary btn-sm" style={{ marginTop: '16px' }}>
          Return to Threat Table
        </button>
      </div>
    );
  }

  let evidenceObj: any = {};
  try {
    evidenceObj = typeof event.evidence_json === 'string' ? JSON.parse(event.evidence_json) : (event.evidence || {});
  } catch (e) {
    evidenceObj = { raw: event.evidence_json };
  }

  return (
    <div className="stack fade-in">
      {/* Top Navigation */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button onClick={onBack} className="btn btn-secondary btn-sm" style={{ gap: 6 }}>
          <ArrowLeft size={14} />
          <span>Back to Threats</span>
        </button>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Event ID: <span className="mono" style={{ color: 'var(--text-secondary)' }}>{event.id}</span>
        </div>
      </div>

      {/* Main Event Header Card */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <span className={`badge badge-${event.severity.toLowerCase()}`}>{event.severity}</span>
              <h2 style={{ fontSize: 20, fontWeight: 700, letterSpacing: '-0.02em' }}>
                {event.attack_type.replace(/_/g, ' ')}
              </h2>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Detection: <strong>{event.detection_method}</strong> &middot; Recorded: <strong>{new Date(event.timestamp).toLocaleString()}</strong>
            </p>
          </div>

          <div style={{
            background: 'var(--bg-elevated)',
            padding: '14px 22px',
            borderRadius: 12,
            textAlign: 'center',
            border: '1px solid var(--border-muted)'
          }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>Risk Score</div>
            <div className="mono" style={{
              fontSize: 28,
              fontWeight: 800,
              color: event.risk_score >= 70 ? 'var(--sev-critical)' : event.risk_score >= 40 ? 'var(--sev-medium)' : 'var(--sev-info)'
            }}>
              {event.risk_score.toFixed(0)} <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>/ 100</span>
            </div>
          </div>
        </div>
      </div>

      {/* Addresses & Telemetry Breakdown */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Server size={15} color="var(--indigo-l)" />
              Network Routing
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              { label: 'Source IP (Attacker)', value: event.source_ip, color: '#fb7185', mono: true },
              { label: 'Destination IP', value: event.destination_ip || 'Internal / N/A', color: 'var(--cyan)', mono: true },
              { label: 'Destination Port', value: event.destination_port || 'Multiple / Swept', color: 'var(--text-primary)', mono: true },
              { label: 'Action Taken', value: event.action_taken, color: event.action_taken.includes('BLOCK') ? '#fb7185' : 'var(--text-secondary)', mono: false },
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
                <span className={row.mono ? 'mono' : ''} style={{ fontWeight: 600, color: row.color, fontSize: 12 }}>{row.value}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={15} color="var(--emerald)" />
              Evidence Summary
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12 }}>
            {Object.entries(evidenceObj).slice(0, 6).map(([key, val]) => (
              <div key={key} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '9px 14px',
                background: 'var(--bg-elevated)',
                borderRadius: 8,
                border: '1px solid var(--border-subtle)'
              }}>
                <span style={{ color: 'var(--text-secondary)' }}>{key.replace(/_/g, ' ')}</span>
                <span className="mono" style={{ fontWeight: 600, color: 'var(--indigo-l)' }}>{String(val)}</span>
              </div>
            ))}
            {Object.keys(evidenceObj).length === 0 && (
              <p style={{ color: 'var(--text-muted)' }}>No structured evidence available.</p>
            )}
          </div>
        </div>
      </div>

      {/* Structured Evidence JSON */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Code size={15} color="var(--indigo-l)" />
            Raw Evidence (JSON)
          </div>
        </div>
        <pre
          className="mono"
          style={{
            background: '#06090f',
            padding: 16,
            borderRadius: 10,
            border: '1px solid rgba(34,211,238,0.12)',
            color: '#7dd3fc',
            fontSize: 12,
            overflowX: 'auto',
            maxHeight: 360,
            lineHeight: 1.7
          }}
        >
          {JSON.stringify(evidenceObj, null, 2)}
        </pre>
      </div>
    </div>
  );
};
