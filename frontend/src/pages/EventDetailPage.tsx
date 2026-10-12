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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Navigation */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button onClick={onBack} className="btn btn-secondary btn-sm" style={{ gap: '6px' }}>
          <ArrowLeft size={14} />
          <span>Back to Threat Records</span>
        </button>
        <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Event ID: <span className="mono" style={{ color: 'var(--text-secondary)' }}>{event.id}</span>
        </div>
      </div>

      {/* Main Event Header Card */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span className={`badge badge-${event.severity.toLowerCase()}`} style={{ fontSize: '0.85rem' }}>
                {event.severity}
              </span>
              <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f8fafc' }}>
                {event.attack_type}
              </h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Detection Method: <strong>{event.detection_method}</strong> | Recorded: <strong>{new Date(event.timestamp).toLocaleString()}</strong>
            </p>
          </div>

          <div style={{
            background: 'var(--bg-tertiary)',
            padding: '12px 24px',
            borderRadius: '8px',
            textAlign: 'center',
            border: '1px solid var(--border-color)'
          }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Risk Score
            </div>
            <div className="mono" style={{ fontSize: '2rem', fontWeight: 800, color: event.risk_score >= 70 ? '#f87171' : '#fde047' }}>
              {event.risk_score.toFixed(1)} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/ 100</span>
            </div>
          </div>
        </div>
      </div>

      {/* Addresses & Telemetry Breakdown */}
      <div className="grid-2">
        <div className="card">
          <div className="card-title">
            <Server size={16} color="var(--accent-cyan)" />
            <span>Target & Endpoint Routing</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Attacking Source IP:</span>
              <span className="mono" style={{ fontWeight: 600, color: '#f87171' }}>{event.source_ip}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Target Host Address:</span>
              <span className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{event.destination_ip || 'Internal / N/A'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Target Destination Port:</span>
              <span className="mono" style={{ fontWeight: 600 }}>{event.destination_port || 'Multiple / Swept'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Defensive Action Taken:</span>
              <span style={{ fontWeight: 600, color: event.action_taken.includes('BLOCK') ? '#f87171' : 'var(--text-secondary)' }}>
                {event.action_taken}
              </span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Activity size={16} color="#34d399" />
            <span>Telemetry Evidence Summary</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '12px', fontSize: '0.85rem' }}>
            {evidenceObj.threshold && (
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Trigger Threshold:</span>
                <span className="mono">{evidenceObj.threshold}</span>
              </div>
            )}
            {evidenceObj.distinct_ports && (
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Distinct Ports Probed:</span>
                <span className="mono">{evidenceObj.distinct_ports}</span>
              </div>
            )}
            {evidenceObj.syn_count && (
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>SYN Packets Observed:</span>
                <span className="mono">{evidenceObj.syn_count}</span>
              </div>
            )}
            {evidenceObj.failed_attempts && (
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Failed Auth Attempts:</span>
                <span className="mono">{evidenceObj.failed_attempts}</span>
              </div>
            )}
            {evidenceObj.span_seconds !== undefined && (
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Observation Window:</span>
                <span className="mono">{evidenceObj.span_seconds}s</span>
              </div>
            )}
            {evidenceObj.scan_type && (
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Scan Pattern Classification:</span>
                <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{evidenceObj.scan_type}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Structured Evidence JSON */}
      <div className="card">
        <div className="card-title">
          <Code size={16} color="var(--accent-cyan)" />
          <span>Full Structured Detection Evidence (JSON)</span>
        </div>
        <pre
          className="mono"
          style={{
            background: '#040812',
            padding: '16px',
            borderRadius: '6px',
            border: '1px solid var(--border-color)',
            color: '#38bdf8',
            fontSize: '0.8rem',
            overflowX: 'auto',
            maxHeight: '360px'
          }}
        >
          {JSON.stringify(evidenceObj, null, 2)}
        </pre>
      </div>
    </div>
  );
};
