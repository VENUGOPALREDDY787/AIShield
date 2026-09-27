import React from 'react';

interface SeverityBreakdownCardProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
}

export const SeverityBreakdownCard: React.FC<SeverityBreakdownCardProps> = ({
  critical,
  high,
  medium,
  low,
  info = 0,
}) => {
  const total = critical + high + medium + low + info || 1;

  const pct = (n: number) => `${Math.round((n / total) * 100)}%`;

  return (
    <div className="card severity-card">
      <div className="card-header">
        <h3>Severity Breakdown</h3>
        <span className="count-pill">{critical + high + medium + low + info} total</span>
      </div>

      <div className="severity-bar-container">
        <div className="severity-segmented-bar">
          {critical > 0 && (
            <div className="segment seg-critical" style={{ width: pct(critical) }} title={`Critical: ${critical}`} />
          )}
          {high > 0 && (
            <div className="segment seg-high" style={{ width: pct(high) }} title={`High: ${high}`} />
          )}
          {medium > 0 && (
            <div className="segment seg-medium" style={{ width: pct(medium) }} title={`Medium: ${medium}`} />
          )}
          {low > 0 && (
            <div className="segment seg-low" style={{ width: pct(low) }} title={`Low: ${low}`} />
          )}
        </div>
      </div>

      <div className="severity-legend-grid">
        <div className="legend-item">
          <span className="legend-dot dot-critical"></span>
          <span className="legend-label">Critical</span>
          <span className="legend-value">{critical}</span>
        </div>
        <div className="legend-item">
          <span className="legend-dot dot-high"></span>
          <span className="legend-label">High</span>
          <span className="legend-value">{high}</span>
        </div>
        <div className="legend-item">
          <span className="legend-dot dot-medium"></span>
          <span className="legend-label">Medium</span>
          <span className="legend-value">{medium}</span>
        </div>
        <div className="legend-item">
          <span className="legend-dot dot-low"></span>
          <span className="legend-label">Low</span>
          <span className="legend-value">{low}</span>
        </div>
      </div>
    </div>
  );
};
