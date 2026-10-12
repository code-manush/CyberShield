import React, { useState, useMemo } from 'react';
import {
  Crosshair,
  Search,
  Filter,
  Eye,
  RefreshCw,
  FileText
} from 'lucide-react';
import { SecurityEvent } from '../types';

interface ThreatDetectionPageProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
  onRefresh: () => void;
}

export const ThreatDetectionPage: React.FC<ThreatDetectionPageProps> = ({
  events,
  onSelectEvent,
  onRefresh
}) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [page, setPage] = useState<number>(0);
  const pageSize = 12;

  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      const matchSearch = searchTerm === '' || 
        ev.source_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (ev.destination_ip && ev.destination_ip.toLowerCase().includes(searchTerm.toLowerCase())) ||
        ev.attack_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ev.id.toLowerCase().includes(searchTerm.toLowerCase());

      const matchType = selectedType === 'ALL' || ev.attack_type === selectedType;
      const matchSev = selectedSeverity === 'ALL' || ev.severity === selectedSeverity;

      return matchSearch && matchType && matchSev;
    });
  }, [events, searchTerm, selectedType, selectedSeverity]);

  const totalPages = Math.ceil(filteredEvents.length / pageSize) || 1;
  const paginatedEvents = filteredEvents.slice(page * pageSize, (page + 1) * pageSize);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Filter and Search Bar Card */}
      <div className="card">
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '14px', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '260px' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              background: 'var(--bg-tertiary)',
              padding: '8px 14px',
              borderRadius: '6px',
              flex: 1,
              border: '1px solid var(--border-color)'
            }}>
              <Search size={16} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="Search by IP, category, or event ID..."
                value={searchTerm}
                onChange={(e) => { setSearchTerm(e.target.value); setPage(0); }}
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem',
                  width: '100%',
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
              <Filter size={15} />
              <span>Category:</span>
              <select
                value={selectedType}
                onChange={(e) => { setSelectedType(e.target.value); setPage(0); }}
                style={{
                  background: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-primary)',
                  padding: '6px 10px',
                  borderRadius: '6px',
                  fontSize: '0.825rem'
                }}
              >
                <option value="ALL">All Categories</option>
                <option value="PORT_SCAN">Port Scan</option>
                <option value="SYN_FLOOD_SUSPECTED">SYN Flood Suspected</option>
                <option value="HIGH_SYN_RATE">High SYN Rate</option>
                <option value="POSSIBLE_DISTRIBUTED_FLOOD">Distributed SYN Flood</option>
                <option value="BRUTE_FORCE_SUSPECTED">Brute Force</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
              <span>Severity:</span>
              <select
                value={selectedSeverity}
                onChange={(e) => { setSelectedSeverity(e.target.value); setPage(0); }}
                style={{
                  background: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-primary)',
                  padding: '6px 10px',
                  borderRadius: '6px',
                  fontSize: '0.825rem'
                }}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Info</option>
              </select>
            </div>

            <button onClick={onRefresh} className="btn btn-secondary btn-sm" title="Refresh Events">
              <RefreshCw size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Events Table Card */}
      <div className="card">
        <div className="card-title" style={{ justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Crosshair size={16} color="var(--accent-cyan)" />
            <span>Recorded Threat Records ({filteredEvents.length} Matching)</span>
          </div>
        </div>

        <div className="table-container" style={{ marginTop: '12px' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>Event Time</th>
                <th>Category</th>
                <th>Source IP</th>
                <th>Destination</th>
                <th>Method</th>
                <th>Risk Score</th>
                <th>Severity</th>
                <th>Defensive Action</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {paginatedEvents.map((ev) => (
                <tr key={ev.id}>
                  <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {new Date(ev.timestamp).toLocaleString()}
                  </td>
                  <td style={{ fontWeight: 600 }}>{ev.attack_type}</td>
                  <td className="mono" style={{ color: 'var(--accent-cyan)' }}>{ev.source_ip}</td>
                  <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                    {ev.destination_ip ? `${ev.destination_ip}${ev.destination_port ? `:${ev.destination_port}` : ''}` : '-'}
                  </td>
                  <td>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {ev.detection_method}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ fontWeight: 700, color: ev.risk_score >= 70 ? '#f87171' : '#fde047' }}>
                        {ev.risk_score.toFixed(1)}
                      </span>
                    </div>
                  </td>
                  <td>
                    <span className={`badge badge-${ev.severity.toLowerCase()}`}>
                      {ev.severity}
                    </span>
                  </td>
                  <td>
                    <span style={{
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      color: ev.action_taken.includes('BLOCK') ? '#f87171' : 'var(--text-secondary)'
                    }}>
                      {ev.action_taken}
                    </span>
                  </td>
                  <td>
                    <button
                      onClick={() => onSelectEvent(ev)}
                      className="btn btn-secondary btn-sm"
                      style={{ gap: '4px' }}
                    >
                      <Eye size={12} />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))}
              {filteredEvents.length === 0 && (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    No security events match the current search filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px', fontSize: '0.825rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>
              Page {page + 1} of {totalPages}
            </span>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                disabled={page === 0}
                onClick={() => setPage(p => Math.max(0, p - 1))}
                className="btn btn-secondary btn-sm"
              >
                Previous
              </button>
              <button
                disabled={page >= totalPages - 1}
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                className="btn btn-secondary btn-sm"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
