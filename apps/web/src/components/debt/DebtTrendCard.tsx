import React from 'react';

interface DebtTrendCardProps {
  trend: 'improving' | 'stable' | 'worsening';
  delta: number;
  newFindingsCount?: number;
  resolvedFindingsCount?: number;
}

export const DebtTrendCard: React.FC<DebtTrendCardProps> = ({
  trend,
  delta,
  newFindingsCount = 0,
  resolvedFindingsCount = 0,
}) => {
  const isPositive = delta > 0.5;
  const isNegative = delta < -0.5;

  return (
    <div className="card trend-card">
      <div className="card-header">
        <h3>Security Debt Velocity</h3>
        <span className="info-tooltip">Compared to previous baseline</span>
      </div>

      <div className={`delta-indicator ${isPositive ? 'positive' : isNegative ? 'negative' : 'neutral'}`}>
        <span className="delta-symbol">{isPositive ? '▲ +' : isNegative ? '▼ ' : '■ '}</span>
        <span className="delta-number">{Math.abs(delta)}</span>
        <span className="delta-label">pts change</span>
      </div>

      <div className="findings-delta-row">
        <div className="delta-box delta-new">
          <span className="delta-box-count">+{newFindingsCount}</span>
          <span className="delta-box-label">New Findings</span>
        </div>
        <div className="delta-box delta-resolved">
          <span className="delta-box-count">-{resolvedFindingsCount}</span>
          <span className="delta-box-label">Resolved</span>
        </div>
      </div>

      <p className="trend-description">
        {trend === 'improving' && 'Security debt is improving due to closed vulnerabilities in recent commits.'}
        {trend === 'worsening' && 'Security debt has increased due to newly detected weaknesses in the PR branch.'}
        {trend === 'stable' && 'Security debt remains stable across recent scans without significant net changes.'}
      </p>
    </div>
  );
};
