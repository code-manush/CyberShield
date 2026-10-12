import React from 'react';
import {
  ShieldAlert,
  Activity,
  Crosshair,
  Lock,
  Cpu,
  ShieldCheck,
  Terminal
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  threatCount: number;
  blockedCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  threatCount,
  blockedCount
}) => {
  const navItems = [
    { id: 'overview', label: 'Security Overview', icon: ShieldAlert, badge: threatCount > 0 ? threatCount : null },
    { id: 'live', label: 'Live Monitoring', icon: Activity, badge: null },
    { id: 'threats', label: 'Threat Detection', icon: Crosshair, badge: threatCount > 0 ? threatCount : null },
    { id: 'prevention', label: 'Prevention Center', icon: Lock, badge: blockedCount > 0 ? blockedCount : null },
    { id: 'ml', label: 'Machine Learning', icon: Cpu, badge: 'RF-1.0' },
  ];

  return (
    <aside className="sidebar">
      <div style={{ padding: '24px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          width: '38px',
          height: '38px',
          borderRadius: '8px',
          background: 'linear-gradient(135deg, #0284c7, #0369a1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 16px rgba(2, 132, 199, 0.4)'
        }}>
          <ShieldCheck size={22} color="#ffffff" />
        </div>
        <div>
          <div style={{ fontWeight: '700', fontSize: '1.05rem', letterSpacing: '0.02em', color: '#f8fafc' }}>
            CYBERSHIELD
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>
            NIDPS PLATFORM
          </div>
        </div>
      </div>

      <nav style={{ padding: '16px 12px', flex: 1, display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 14px',
                borderRadius: '6px',
                border: 'none',
                background: isActive ? 'rgba(56, 189, 248, 0.12)' : 'transparent',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                fontSize: '0.875rem',
                fontWeight: isActive ? 600 : 500,
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease'
              }}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <Icon size={18} />
                <span>{item.label}</span>
              </div>
              {item.badge !== null && (
                <span style={{
                  padding: '2px 7px',
                  borderRadius: '10px',
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  background: isActive ? 'var(--accent-cyan)' : 'var(--bg-tertiary)',
                  color: isActive ? '#090d16' : 'var(--text-secondary)'
                }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div style={{ padding: '16px', borderTop: '1px solid var(--border-color)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <div className="pulse-dot" />
          <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>Active Engine</span>
        </div>
        <div>FastAPI + Scapy + Random Forest</div>
        <div style={{ marginTop: '4px', fontSize: '0.7rem' }}>CyberShield v1.0.0</div>
      </div>
    </aside>
  );
};
