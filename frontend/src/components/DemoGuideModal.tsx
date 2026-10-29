import React from 'react';
import {
  X,
  GraduationCap,
  Flame,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  ArrowRight,
  CheckCircle,
  Copy,
  Terminal,
  Activity
} from 'lucide-react';

interface DemoGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTab: (tab: string) => void;
  onStartAttack?: (attackType: string, autoEnforce: boolean) => Promise<void>;
}

export const DemoGuideModal: React.FC<DemoGuideModalProps> = ({
  isOpen,
  onClose,
  onNavigateTab,
  onStartAttack
}) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', borderBottom: '1px solid var(--border-color)', paddingBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #0284c7, #6366f1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <GraduationCap size={20} color="#ffffff" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Professor Presentation Walkthrough</h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Step-by-step 3-minute demonstration script for your evaluation
              </p>
            </div>
          </div>

          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Step 1 */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '10px', borderLeft: '4px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: 700, color: 'var(--accent-cyan)', fontSize: '0.9rem' }}>STEP 1: THE ELEVATOR PITCH (30 SECONDS)</span>
              <span className="badge badge-accent">ARCHITECTURE</span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '8px' }}>
              <em>"Professor, CyberShield is an enterprise-grade Network Intrusion Detection & Prevention System. It uses a <strong>hybrid architecture</strong>: sub-millisecond $O(1)$ sliding-window rule engines for instantaneous flood detection, paired with a Supervised Random Forest AI model to classify network flows, and stateful automated firewall blocking."</em>
            </p>
          </div>

          {/* Step 2 */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '10px', borderLeft: '4px solid #ef4444' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: 700, color: '#f87171', fontSize: '0.9rem' }}>STEP 2: LAUNCH LIVE ATTACK (1 MINUTE)</span>
              <span className="badge badge-critical">LIVE DEMO</span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '12px' }}>
              Navigate to the <strong>Live Attack Lab</strong> and click <strong>"Launch Port Scan"</strong> or <strong>"Launch SYN Flood"</strong>.
              Point out the live packets streaming in real-time, the throughput graph spiking, and the immediate alarm trigger.
            </p>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => {
                  onClose();
                  onNavigateTab('attack-lab');
                }}
              >
                <Flame size={14} />
                <span>Go to Live Attack Lab</span>
              </button>
            </div>
          </div>

          {/* Step 3 */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '10px', borderLeft: '4px solid #f59e0b' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: 700, color: '#fbbf24', fontSize: '0.9rem' }}>STEP 3: EXPLAIN THREAT SCORING & DETAILS (45 SECONDS)</span>
              <span className="badge badge-medium">DETECTION</span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '12px' }}>
              Open <strong>Threat Detection</strong>. Click on the detected event. Show the professor the <strong>Risk Score (0–100)</strong>, the list of probed ports or arrival rates, and explain that scores are calculated dynamically based on attack burst and target sensitivity.
            </p>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => {
                onClose();
                onNavigateTab('threats');
              }}
            >
              <ShieldAlert size={14} />
              <span>Go to Threat Detection</span>
            </button>
          </div>

          {/* Step 4 */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '10px', borderLeft: '4px solid #10b981' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: 700, color: '#34d399', fontSize: '0.9rem' }}>STEP 4: AUTOMATED PREVENTION & IP BLOCKING (45 SECONDS)</span>
              <span className="badge badge-info">DEFENSE</span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '12px' }}>
              Open <strong>Prevention Center</strong>. Show that in <strong>ENFORCE</strong> mode, CyberShield automatically blocked the attacker's IP (e.g. <code className="mono">198.51.100.42</code>) with a temporary 300-second lease to protect the network. Explain that loopback and management IPs are protected by an allowlist.
            </p>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => {
                onClose();
                onNavigateTab('prevention');
              }}
            >
              <ShieldCheck size={14} />
              <span>Go to Prevention Center</span>
            </button>
          </div>

          {/* Step 5 */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '10px', borderLeft: '4px solid #818cf8' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: 700, color: '#818cf8', fontSize: '0.9rem' }}>STEP 5: MACHINE LEARNING & TESTS (30 SECONDS)</span>
              <span className="badge" style={{ background: 'rgba(129, 140, 248, 0.2)', color: '#c7d2fe' }}>AI CLASSIFIER</span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '12px' }}>
              Open <strong>Machine Learning</strong>. Show the Random Forest Confusion Matrix (1,200 held-out test flows) and top feature importances (packet lengths, backward byte rates). Mention that CyberShield includes <strong>37 passing automated tests</strong> in pytest.
            </p>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => {
                onClose();
                onNavigateTab('ml');
              }}
            >
              <Cpu size={14} />
              <span>Go to Machine Learning</span>
            </button>
          </div>
        </div>

        <div style={{ marginTop: '24px', textAlign: 'right' }}>
          <button className="btn btn-primary" onClick={onClose}>
            Got it, ready to present!
          </button>
        </div>
      </div>
    </div>
  );
};
