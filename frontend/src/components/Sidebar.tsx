import React from 'react';
import {
  ShieldAlert,
  Activity,
  Crosshair,
  Lock,
  Cpu,
  ShieldCheck,
  FlaskConical,
  Zap
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
    {
      group: 'MONITORING',
      items: [
        { id: 'overview',   label: 'Overview',          icon: ShieldAlert, badge: threatCount > 0 ? String(threatCount) : null, badgeVariant: 'alert' as const },
        { id: 'live',       label: 'Live Monitoring',   icon: Activity,    badge: null },
        { id: 'threats',    label: 'Threat Detection',  icon: Crosshair,   badge: threatCount > 0 ? String(threatCount) : null, badgeVariant: 'alert' as const },
      ]
    },
    {
      group: 'DEFENSE',
      items: [
        { id: 'prevention', label: 'Prevention Center', icon: Lock,    badge: blockedCount > 0 ? String(blockedCount) : null, badgeVariant: 'default' as const },
        { id: 'ml',         label: 'ML Classifier',     icon: Cpu,     badge: 'RF', badgeVariant: 'default' as const },
      ]
    },
    {
      group: 'LAB',
      items: [
        { id: 'attack-lab', label: 'Attack Lab',        icon: FlaskConical, badge: 'DEMO', badgeVariant: 'default' as const },
      ]
    }
  ];

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">
          <ShieldCheck size={20} color="#fff" />
        </div>
        <div>
          <div className="sidebar-logo-name">CYBERSHIELD</div>
          <div className="sidebar-logo-sub">NIDPS Platform</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {navItems.map((group) => (
          <div key={group.group}>
            <div className="sidebar-label">{group.group}</div>
            {group.items.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-${item.id}`}
                  onClick={() => setActiveTab(item.id)}
                  className={`nav-item${isActive ? ' active' : ''}`}
                >
                  <span className="nav-item-left">
                    <Icon size={16} />
                    <span>{item.label}</span>
                  </span>
                  {item.badge && (
                    <span className={`nav-badge${item.badgeVariant === 'alert' && !isActive ? ' nav-badge-alert' : ''}`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <div className="sidebar-status">
          <span className="dot dot-green" />
          <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Engine Active</span>
        </div>
        <div className="sidebar-version" style={{ marginTop: 6 }}>
          <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>FastAPI · Scapy · Random Forest</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 2 }}>CyberShield v1.0.0</div>
        </div>
      </div>
    </aside>
  );
};
