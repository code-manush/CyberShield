import React from 'react';
import {
  Cpu,
  CheckCircle2,
  Target,
  TrendingUp,
  AlertOctagon,
  Database,
  Layers
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell
} from 'recharts';
import { MLMetrics } from '../types';

interface MachineLearningPageProps {
  metrics: MLMetrics | null;
}

const TT = {
  contentStyle: {
    background: '#1e2330',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: 10,
    fontSize: 12,
    boxShadow: '0 8px 24px rgba(0,0,0,0.5)'
  }
};

export const MachineLearningPage: React.FC<MachineLearningPageProps> = ({ metrics }) => {
  const isTrained = metrics?.is_trained ?? false;

  const featureData = metrics?.feature_importances
    ? Object.entries(metrics.feature_importances).slice(0, 8).map(([name, imp]) => ({
        name: name.replace(/_/g, ' '),
        importance: Math.round(imp * 1000) / 10
      }))
    : [];

  const cm      = metrics?.confusion_matrix || [[0, 0, 0], [0, 0, 0], [0, 0, 0]];
  const classes = metrics?.classes || ['BENIGN', 'PORT_SCAN', 'SYN_FLOOD'];

  const metricCards = [
    {
      label: 'Test Accuracy',
      value: isTrained ? `${((metrics?.accuracy ?? 0) * 100).toFixed(1)}%` : '—',
      sub: `${metrics?.test_set_size ?? 0} test samples`,
      icon: Target,
      color: '#6366f1',
      bg: 'rgba(99,102,241,0.12)'
    },
    {
      label: 'Macro F1-Score',
      value: isTrained ? (metrics?.f1_score ?? 0).toFixed(4) : '—',
      sub: `P: ${metrics?.precision?.toFixed(3)} · R: ${metrics?.recall?.toFixed(3)}`,
      icon: TrendingUp,
      color: '#34d399',
      bg: 'rgba(52,211,153,0.12)'
    },
    {
      label: 'False Positive Rate',
      value: isTrained ? `${((metrics?.false_positive_rate ?? 0) * 100).toFixed(2)}%` : '—',
      sub: 'Benign misclassifications',
      icon: AlertOctagon,
      color: '#fb923c',
      bg: 'rgba(251,146,60,0.12)'
    },
    {
      label: 'Training Corpus',
      value: metrics?.training_set_size ?? 0,
      sub: '80/20 train/test split',
      icon: Database,
      color: '#a78bfa',
      bg: 'rgba(167,139,250,0.12)'
    }
  ];

  const featureColors = ['#6366f1', '#818cf8', '#22d3ee', '#34d399', '#a78bfa', '#fb923c', '#f43f5e', '#60a5fa'];

  return (
    <div className="stack fade-in">
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">ML Classifier</h1>
          <p className="page-desc">Random Forest intrusion detection model — performance metrics and evaluation</p>
        </div>
        <span className={`badge ${isTrained ? 'badge-info' : 'badge-neutral'}`} style={{ fontSize: 12, padding: '5px 12px' }}>
          <CheckCircle2 size={13} />
          {isTrained ? 'Model Active (v1.0)' : 'Not Trained'}
        </span>
      </div>

      {/* Model summary banner */}
      <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
        <div style={{
          width: 52,
          height: 52,
          borderRadius: 14,
          background: 'rgba(99,102,241,0.15)',
          border: '1px solid rgba(99,102,241,0.25)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0
        }}>
          <Cpu size={24} color="var(--indigo-l)" />
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>
            RandomForestClassifier — 100 Trees · Max Depth 12
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Supervised multi-class classifier trained on bidirectional network flow representations.
            Features include SYN ratios, byte counts, packet rates, and ACK flags.
          </div>
        </div>
        {isTrained && (
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {[
              { label: 'Classes', value: classes.length },
              { label: 'Features', value: Object.keys(metrics?.feature_importances ?? {}).length },
            ].map((s) => (
              <div key={s.label} style={{ textAlign: 'center', padding: '10px 18px', background: 'var(--bg-elevated)', borderRadius: 10, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--indigo-l)' }}>{s.value}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{s.label}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Metric cards */}
      <div className="grid-4">
        {metricCards.map((m) => {
          const Icon = m.icon;
          return (
            <div key={m.label} className="card metric-card">
              <div className="metric-card-icon" style={{ background: m.bg }}>
                <Icon size={18} color={m.color} />
              </div>
              <div className="metric-card-value mono" style={{ color: m.color }}>{m.value}</div>
              <div className="metric-card-label">{m.label}</div>
              <div className="metric-card-sub">{m.sub}</div>
            </div>
          );
        })}
      </div>

      {/* Confusion matrix + comparison */}
      <div className="grid-2">
        {/* Confusion matrix */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Layers size={15} color="var(--indigo-l)" />
              Confusion Matrix
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Rows = True, Cols = Predicted</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '100px repeat(3, 1fr)', gap: 6 }}>
            {/* Header row */}
            <div />
            {classes.map((c) => (
              <div key={c} style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textAlign: 'center', padding: '4px 0' }}>
                {c.replace(/_/g, ' ')}
              </div>
            ))}

            {/* Data rows */}
            {classes.map((actualClass, rowIdx) => (
              <React.Fragment key={actualClass}>
                <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center' }}>
                  {actualClass.replace(/_/g, ' ')}
                </div>
                {classes.map((_, colIdx) => {
                  const val    = cm[rowIdx]?.[colIdx] ?? 0;
                  const isDiag = rowIdx === colIdx;
                  return (
                    <div
                      key={colIdx}
                      className="mono"
                      style={{
                        padding: '12px 6px',
                        borderRadius: 8,
                        textAlign: 'center',
                        background: isDiag ? 'rgba(99,102,241,0.15)' : val > 0 ? 'rgba(244,63,94,0.1)' : 'var(--bg-elevated)',
                        border: `1px solid ${isDiag ? 'rgba(99,102,241,0.3)' : val > 0 ? 'rgba(244,63,94,0.2)' : 'var(--border-subtle)'}`,
                        fontWeight: 700,
                        fontSize: 15,
                        color: isDiag ? 'var(--indigo-l)' : val > 0 ? '#fb7185' : 'var(--text-muted)'
                      }}
                    >
                      {val}
                    </div>
                  );
                })}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Baseline comparison */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Baseline Comparison</div>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
            Random Forest vs. deterministic threshold heuristics on the same test partition.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              {
                label: 'Random Forest Accuracy',
                sub: '100-tree supervised ensemble',
                value: metrics ? `${(metrics.accuracy * 100).toFixed(1)}%` : '—',
                color: 'var(--indigo-l)'
              },
              {
                label: 'Rule-Based Baseline',
                sub: 'Deterministic thresholds',
                value: metrics?.baseline_comparison?.baseline_accuracy
                  ? `${(metrics.baseline_comparison.baseline_accuracy * 100).toFixed(1)}%`
                  : '100.0%',
                color: 'var(--text-secondary)'
              },
              {
                label: 'F1 Improvement Δ',
                sub: 'Performance gain',
                value: `+${metrics?.baseline_comparison?.ml_f1_improvement?.toFixed(4) ?? '0.0000'}`,
                color: 'var(--emerald)'
              }
            ].map((row) => (
              <div key={row.label} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px 16px',
                background: 'var(--bg-elevated)',
                borderRadius: 10,
                border: '1px solid var(--border-subtle)'
              }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{row.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{row.sub}</div>
                </div>
                <div className="mono" style={{ fontWeight: 700, fontSize: 16, color: row.color }}>{row.value}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Feature importances */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Top Feature Importances (Gini)</div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Flow signature weights</span>
        </div>
        <div style={{ height: 260, marginTop: 8 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={featureData} layout="vertical" barCategoryGap="25%">
              <XAxis type="number" stroke="#545d6d" fontSize={11} tickLine={false} axisLine={false} unit="%" />
              <YAxis dataKey="name" type="category" stroke="#545d6d" fontSize={11} tickLine={false} axisLine={false} width={150} />
              <Tooltip {...TT} formatter={(val: any) => [`${val}%`, 'Importance']} />
              <Bar dataKey="importance" radius={[0, 6, 6, 0]}>
                {featureData.map((_, i) => (
                  <Cell key={i} fill={featureColors[i % featureColors.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
