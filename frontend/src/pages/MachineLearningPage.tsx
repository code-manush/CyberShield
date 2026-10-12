import React from 'react';
import {
  Cpu,
  CheckCircle,
  Database,
  BarChart3,
  Layers,
  Award
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

export const MachineLearningPage: React.FC<MachineLearningPageProps> = ({ metrics }) => {
  const isTrained = metrics?.is_trained ?? false;

  const featureData = metrics?.feature_importances
    ? Object.entries(metrics.feature_importances).slice(0, 8).map(([name, imp]) => ({
        name: name.replace(/_/g, ' '),
        importance: Math.round(imp * 1000) / 10 // as percentage
      }))
    : [];

  const cm = metrics?.confusion_matrix || [[0, 0, 0], [0, 0, 0], [0, 0, 0]];
  const classes = metrics?.classes || ['BENIGN', 'PORT_SCAN', 'SYN_FLOOD'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Overview & Status Banner */}
      <div className="card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div className="card-title" style={{ marginBottom: '6px' }}>
            <Cpu size={18} color="var(--accent-cyan)" />
            <span>Intrusion Detection Classifier Status</span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Supervised Random Forest trained on bidirectional network flow representations (duration, bytes, packet rates, SYN ratios).
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className={`badge ${isTrained ? 'badge-info' : 'badge-low'}`}>
            <CheckCircle size={14} />
            <span>{isTrained ? 'MODEL ACTIVE (v1.0)' : 'UNTRAINED'}</span>
          </span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid-4">
        <div className="card">
          <div className="card-title">
            <Award size={16} color="var(--accent-cyan)" />
            <span>Test Accuracy</span>
          </div>
          <div className="mono" style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
            {isTrained ? `${((metrics?.accuracy ?? 0) * 100).toFixed(1)}%` : '-'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Test samples: {metrics?.test_set_size ?? 0}
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <BarChart3 size={16} color="#34d399" />
            <span>Macro F1-Score</span>
          </div>
          <div className="mono" style={{ fontSize: '2rem', fontWeight: 700, color: '#34d399' }}>
            {isTrained ? (metrics?.f1_score ?? 0).toFixed(4) : '-'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Precision: {metrics?.precision?.toFixed(4)} | Recall: {metrics?.recall?.toFixed(4)}
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Layers size={16} color="#f97316" />
            <span>False-Positive Rate</span>
          </div>
          <div className="mono" style={{ fontSize: '2rem', fontWeight: 700, color: '#f97316' }}>
            {isTrained ? `${((metrics?.false_positive_rate ?? 0) * 100).toFixed(2)}%` : '-'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Benign misclassifications
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Database size={16} color="#a855f7" />
            <span>Training Corpus</span>
          </div>
          <div className="mono" style={{ fontSize: '2rem', fontWeight: 700, color: '#a855f7' }}>
            {metrics?.training_set_size ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Held-out validation: 20%
          </div>
        </div>
      </div>

      {/* Confusion Matrix & Baseline Comparison */}
      <div className="grid-2">
        {/* Confusion Matrix */}
        <div className="card">
          <div className="card-title">
            <span>Held-Out Confusion Matrix</span>
          </div>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
            Rows indicate Ground Truth classes; columns indicate Model Predictions.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '120px repeat(3, 1fr)', gap: '8px', textAlign: 'center' }}>
            <div />
            {classes.map(c => (
              <div key={c} style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                Pred {c.replace('_', ' ')}
              </div>
            ))}

            {classes.map((actualClass, rowIdx) => (
              <React.Fragment key={actualClass}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, textAlign: 'left', color: 'var(--text-secondary)' }}>
                  True {actualClass.replace('_', ' ')}
                </div>
                {classes.map((_, colIdx) => {
                  const val = cm[rowIdx]?.[colIdx] ?? 0;
                  const isDiag = rowIdx === colIdx;
                  return (
                    <div
                      key={colIdx}
                      className="mono"
                      style={{
                        padding: '12px 8px',
                        borderRadius: '6px',
                        background: isDiag ? 'rgba(56, 189, 248, 0.15)' : 'rgba(239, 68, 68, 0.1)',
                        border: `1px solid ${isDiag ? 'rgba(56, 189, 248, 0.3)' : 'rgba(239, 68, 68, 0.2)'}`,
                        fontWeight: 700,
                        color: isDiag ? '#38bdf8' : '#f87171'
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

        {/* Baseline Comparison */}
        <div className="card">
          <div className="card-title">
            <span>Model vs. Rule-Based Baseline Comparison</span>
          </div>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
            Comparison against deterministic threshold heuristics on identical test partitions.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <div>
                <div style={{ fontWeight: 600 }}>Random Forest Accuracy</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Supervised 100-tree ensemble</div>
              </div>
              <div className="mono" style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                {metrics ? `${(metrics.accuracy * 100).toFixed(1)}%` : '-'}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <div>
                <div style={{ fontWeight: 600 }}>Rule-Based Baseline Accuracy</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Deterministic threshold logic</div>
              </div>
              <div className="mono" style={{ fontSize: '1.25rem', fontWeight: 700, color: '#94a3b8' }}>
                {metrics?.baseline_comparison?.baseline_accuracy ? `${(metrics.baseline_comparison.baseline_accuracy * 100).toFixed(1)}%` : '100.0%'}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 14px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              <div>
                <div style={{ fontWeight: 600 }}>Classification Delta</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>F1 performance improvement</div>
              </div>
              <div className="mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: '#34d399' }}>
                +{metrics?.baseline_comparison?.ml_f1_improvement?.toFixed(4) ?? '0.0000'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Feature Importances Bar Chart */}
      <div className="card">
        <div className="card-title">
          <span>Top Gini Feature Importances (Flow Signatures)</span>
        </div>
        <div style={{ height: '240px', marginTop: '12px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={featureData} layout="vertical">
              <XAxis type="number" stroke="#475569" fontSize={11} tickLine={false} unit="%" />
              <YAxis dataKey="name" type="category" stroke="#475569" fontSize={11} tickLine={false} width={160} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '6px' }}
                formatter={(val: any) => [`${val}%`, 'Importance']}
              />
              <Bar dataKey="importance" fill="#38bdf8" radius={[0, 4, 4, 0]}>
                {featureData.map((_, index) => (
                  <Cell key={`feat-cell-${index}`} fill={index === 0 ? '#38bdf8' : index === 1 ? '#818cf8' : '#60a5fa'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
