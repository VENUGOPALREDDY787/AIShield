import React from 'react';
import type { DebtHistoryEntry } from '../../types/index.js';

interface DebtTrendChartProps {
  history: DebtHistoryEntry[];
  height?: number;
}

export const DebtTrendChart: React.FC<DebtTrendChartProps> = ({ history, height = 180 }) => {
  if (!history || history.length === 0) {
    return (
      <div className="card chart-card">
        <div className="card-header">
          <h3>Security Debt Longitudinal Trend</h3>
        </div>
        <div className="empty-state">No historical debt data recorded yet.</div>
      </div>
    );
  }

  // Sort chronological (oldest to newest)
  const points = [...history].sort(
    (a, b) => new Date(a.recordedAt).getTime() - new Date(b.recordedAt).getTime(),
  );

  const width = 600;
  const paddingX = 40;
  const paddingY = 30;
  const graphWidth = width - paddingX * 2;
  const graphHeight = height - paddingY * 2;

  const minScore = 0;
  const maxScore = 100;

  const getX = (idx: number) => {
    if (points.length <= 1) return paddingX + graphWidth / 2;
    return paddingX + (idx / (points.length - 1)) * graphWidth;
  };

  const getY = (score: number) => {
    const norm = (score - minScore) / (maxScore - minScore);
    return height - paddingY - norm * graphHeight;
  };

  const pathD = points
    .map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${getX(idx)} ${getY(p.overallScore)}`)
    .join(' ');

  const areaD = `${pathD} L ${getX(points.length - 1)} ${height - paddingY} L ${getX(0)} ${
    height - paddingY
  } Z`;

  return (
    <div className="card chart-card">
      <div className="card-header">
        <h3>Security Debt Score Trend</h3>
        <span className="info-tooltip">{points.length} recorded events</span>
      </div>

      <div className="chart-container">
        <svg viewBox={`0 0 ${width} ${height}`} className="trend-svg" preserveAspectRatio="none">
          <defs>
            <linearGradient id="scoreAreaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line
            x1={paddingX}
            y1={getY(100)}
            x2={width - paddingX}
            y2={getY(100)}
            stroke="var(--border-color)"
            strokeDasharray="4 4"
          />
          <line
            x1={paddingX}
            y1={getY(75)}
            x2={width - paddingX}
            y2={getY(75)}
            stroke="var(--border-color)"
            strokeDasharray="4 4"
          />
          <line
            x1={paddingX}
            y1={getY(50)}
            x2={width - paddingX}
            y2={getY(50)}
            stroke="var(--border-color)"
            strokeDasharray="4 4"
          />
          <line
            x1={paddingX}
            y1={getY(0)}
            x2={width - paddingX}
            y2={getY(0)}
            stroke="var(--border-color)"
          />

          {/* Area under curve */}
          <path d={areaD} fill="url(#scoreAreaGradient)" />

          {/* Score line */}
          <path d={pathD} fill="none" stroke="#3b82f6" strokeWidth="3" strokeLinecap="round" />

          {/* Data points */}
          {points.map((p, idx) => {
            const x = getX(idx);
            const y = getY(p.overallScore);
            return (
              <g key={p.id || idx}>
                <circle cx={x} cy={y} r="5" fill="#1e293b" stroke="#3b82f6" strokeWidth="2.5" />
                <text
                  x={x}
                  y={y - 10}
                  textAnchor="middle"
                  fill="var(--text-primary)"
                  fontSize="11"
                  fontWeight="600"
                >
                  {Math.round(p.overallScore)}
                </text>
              </g>
            );
          })}
        </svg>

        <div className="chart-axis-labels">
          {points.map((p, idx) => (
            <span key={p.id || idx} className="axis-label">
              {new Date(p.recordedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};
