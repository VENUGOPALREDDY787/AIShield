import React from 'react';

interface DebtScoreCardProps {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  totalPoints: number;
  activeFindings: number;
}

export const DebtScoreCard: React.FC<DebtScoreCardProps> = ({
  score,
  grade,
  riskLevel = 'MEDIUM',
  totalPoints,
  activeFindings,
}) => {
  const getGradeColor = (g: string) => {
    switch (g) {
      case 'A':
        return 'var(--accent-green)';
      case 'B':
        return 'var(--accent-blue)';
      case 'C':
        return 'var(--accent-yellow)';
      case 'D':
        return '#f97316';
      case 'F':
      default:
        return 'var(--accent-red)';
    }
  };

  const getRiskBadgeClass = (risk: string) => {
    switch (risk) {
      case 'LOW':
        return 'badge-success';
      case 'MEDIUM':
        return 'badge-warning';
      case 'HIGH':
      case 'CRITICAL':
        return 'badge-danger';
      default:
        return 'badge-neutral';
    }
  };

  return (
    <div className="card debt-card">
      <div className="card-header">
        <div>
          <h3>Security Debt Score</h3>
          <span className="info-tooltip">100 = Clean, 0 = High Debt</span>
        </div>
        <span className={`badge ${getRiskBadgeClass(riskLevel)}`}>{riskLevel} RISK</span>
      </div>

      <div className="debt-score-display">
        <div className="score-circle" style={{ borderColor: getGradeColor(grade) }}>
          <span className="score-value">{Math.round(score * 10) / 10}</span>
          <span className="score-denom">/100</span>
        </div>
        <div className="score-meta">
          <div className="grade-badge" style={{ backgroundColor: getGradeColor(grade) }}>
            Grade {grade}
          </div>
          <p className="score-description">
            {score >= 90
              ? 'Excellent security posture with negligible technical debt.'
              : score >= 75
              ? 'Good security posture. Minor issues requiring scheduled triage.'
              : score >= 50
              ? 'Moderate security debt. High-priority findings require remediation.'
              : 'Critical security debt. Immediate remediation required before merging.'}
          </p>
        </div>
      </div>

      <div className="debt-stats-grid">
        <div className="debt-stat">
          <span className="stat-label">Accumulated Debt Points</span>
          <span className="stat-value">{totalPoints} pts</span>
        </div>
        <div className="debt-stat">
          <span className="stat-label">Active Findings</span>
          <span className="stat-value">{activeFindings}</span>
        </div>
      </div>
    </div>
  );
};
