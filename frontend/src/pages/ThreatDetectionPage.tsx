import React, { useState, useMemo } from 'react';
import {
  Search,
  SlidersHorizontal,
  Eye,
  RefreshCw,
  ShieldAlert
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
  const [searchTerm, setSearchTerm]         = useState('');
  const [selectedType, setSelectedType]     = useState('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [page, setPage] = useState(0);
  const pageSize = 15;

  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      const q = searchTerm.toLowerCase();
      const matchSearch = !q ||
        ev.source_ip.toLowerCase().includes(q) ||
        (ev.destination_ip?.toLowerCase().includes(q)) ||
        ev.attack_type.toLowerCase().includes(q) ||
        ev.id.toLowerCase().includes(q);
      const matchType = selectedType === 'ALL' || ev.attack_type === selectedType;
      const matchSev  = selectedSeverity === 'ALL' || ev.severity === selectedSeverity;
      return matchSearch && matchType && matchSev;
    });
  }, [events, searchTerm, selectedType, selectedSeverity]);

  const totalPages    = Math.ceil(filteredEvents.length / pageSize) || 1;
  const paginatedEvents = filteredEvents.slice(page * pageSize, (page + 1) * pageSize);

  const riskColor = (score: number) =>
    score >= 70 ? 'var(--sev-critical)' : score >= 40 ? 'var(--sev-medium)' : 'var(--sev-info)';

  return (
    <div className="stack fade-in">
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Detection</h1>
          <p className="page-desc">{filteredEvents.length} matching security events</p>
        </div>
        <button onClick={onRefresh} className="btn btn-secondary btn-sm" title="Refresh">
          <RefreshCw size={13} />
          Refresh
        </button>
      </div>

      {/* Filter bar */}
      <div className="card" style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Search */}
          <div className="search-wrap" style={{ flex: 1, minWidth: 240 }}>
            <Search size={14} color="var(--text-muted)" />
            <input
              id="threat-search"
              type="text"
              placeholder="Search IP, attack type, event ID…"
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setPage(0); }}
            />
          </div>

          {/* Category filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <SlidersHorizontal size={13} color="var(--text-muted)" />
            <select
              id="filter-category"
              className="input"
              style={{ width: 180 }}
              value={selectedType}
              onChange={(e) => { setSelectedType(e.target.value); setPage(0); }}
            >
              <option value="ALL">All Categories</option>
              <option value="PORT_SCAN">Port Scan</option>
              <option value="SYN_FLOOD_SUSPECTED">SYN Flood</option>
              <option value="HIGH_SYN_RATE">High SYN Rate</option>
              <option value="POSSIBLE_DISTRIBUTED_FLOOD">Distributed Flood</option>
              <option value="BRUTE_FORCE_SUSPECTED">Brute Force</option>
            </select>
          </div>

          {/* Severity filter */}
          <select
            id="filter-severity"
            className="input"
            style={{ width: 150 }}
            value={selectedSeverity}
            onChange={(e) => { setSelectedSeverity(e.target.value); setPage(0); }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShieldAlert size={15} color="var(--indigo-l)" />
          <span style={{ fontWeight: 600, fontSize: 13 }}>
            Threat Records
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 4 }}>
            {filteredEvents.length} results
          </span>
        </div>

        <div className="table-container" style={{ border: 'none', borderRadius: 0 }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Category</th>
                <th>Source IP</th>
                <th>Destination</th>
                <th>Method</th>
                <th>Risk</th>
                <th>Severity</th>
                <th>Action Taken</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {paginatedEvents.map((ev) => (
                <tr key={ev.id}>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {new Date(ev.timestamp).toLocaleString()}
                  </td>
                  <td style={{ fontWeight: 600, fontSize: 12 }}>
                    {ev.attack_type.replace(/_/g, ' ')}
                  </td>
                  <td className="mono" style={{ color: 'var(--cyan)', fontSize: 12 }}>
                    {ev.source_ip}
                  </td>
                  <td className="mono" style={{ color: 'var(--text-secondary)', fontSize: 11 }}>
                    {ev.destination_ip
                      ? `${ev.destination_ip}${ev.destination_port ? `:${ev.destination_port}` : ''}`
                      : '—'}
                  </td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {ev.detection_method}
                  </td>
                  <td>
                    <span style={{ fontWeight: 700, color: riskColor(ev.risk_score), fontSize: 13 }}>
                      {ev.risk_score.toFixed(0)}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${ev.severity.toLowerCase()}`}>
                      {ev.severity}
                    </span>
                  </td>
                  <td style={{ fontSize: 11, fontWeight: 600, color: ev.action_taken.includes('BLOCK') ? '#fb7185' : 'var(--text-muted)' }}>
                    {ev.action_taken}
                  </td>
                  <td>
                    <button onClick={() => onSelectEvent(ev)} className="btn btn-ghost btn-xs" style={{ gap: 4 }}>
                      <Eye size={12} />
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
              {filteredEvents.length === 0 && (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                    No events match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '12px 20px',
            borderTop: '1px solid var(--border-subtle)'
          }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Page {page + 1} of {totalPages} &nbsp;·&nbsp; {filteredEvents.length} total
            </span>
            <div style={{ display: 'flex', gap: 6 }}>
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
