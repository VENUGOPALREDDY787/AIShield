import React from 'react';
import type { PullRequestSummary } from '../../types/index.js';
import { Badge } from '../common/Badge.js';

interface PullRequestTableProps {
  pullRequests: PullRequestSummary[];
  onSelectPR?: (prId: string) => void;
}

export const PullRequestTable: React.FC<PullRequestTableProps> = ({
  pullRequests,
  onSelectPR,
}) => {
  return (
    <div className="card pr-card">
      <div className="card-header">
        <div>
          <h3>Pull Request Security Reviews</h3>
          <span className="info-tooltip">PR Risk Deltas & Check Status</span>
        </div>
        <span className="count-pill">{pullRequests.length} active PRs</span>
      </div>

      <div className="table-responsive">
        <table className="data-table">
          <thead>
            <tr>
              <th>PR</th>
              <th>Status</th>
              <th>Title & Author</th>
              <th>Branches</th>
              <th>Security Check</th>
              <th>Debt Impact</th>
              <th>New vs Resolved</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {pullRequests.length === 0 ? (
              <tr>
                <td colSpan={8} className="empty-state">
                  No pull requests analyzed yet.
                </td>
              </tr>
            ) : (
              pullRequests.map((pr) => {
                const isPositive = pr.scoreDelta > 0;
                const isNegative = pr.scoreDelta < 0;

                return (
                  <tr
                    key={pr.id}
                    className="clickable-row"
                    onClick={() => onSelectPR?.(pr.id)}
                  >
                    <td>
                      <strong className="pr-number">#{pr.number}</strong>
                    </td>
                    <td>
                      <Badge label={pr.status.toUpperCase()} variant="neutral" size="sm" />
                    </td>
                    <td className="pr-title-cell">
                      <div className="pr-title-wrapper">
                        <span className="pr-title-text">{pr.title}</span>
                        <span className="pr-author">by @{pr.author}</span>
                      </div>
                    </td>
                    <td>
                      <code className="branch-name">{pr.sourceBranch}</code> →{' '}
                      <code className="branch-name">{pr.targetBranch}</code>
                    </td>
                    <td>
                      <Badge
                        label={pr.checkStatus || (pr.findingsIntroduced > 0 ? 'FAIL' : 'PASS')}
                        variant={pr.checkStatus === 'FAIL' ? 'danger' : 'success'}
                      />
                    </td>
                    <td>
                      <span
                        className={`delta-badge ${
                          isPositive ? 'debt-better' : isNegative ? 'debt-worse' : 'debt-neutral'
                        }`}
                      >
                        {isPositive ? `+${pr.scoreDelta} pts` : isNegative ? `${pr.scoreDelta} pts` : '0 pts'}
                      </span>
                    </td>
                    <td>
                      <span className="pr-findings-summary">
                        {pr.findingsIntroduced > 0 && (
                          <span className="count-new">+{pr.findingsIntroduced} new</span>
                        )}
                        {pr.findingsResolved > 0 && (
                          <span className="count-resolved"> -{pr.findingsResolved} fixed</span>
                        )}
                        {pr.findingsIntroduced === 0 && pr.findingsResolved === 0 && (
                          <span className="count-clean">Clean</span>
                        )}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn-link"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectPR?.(pr.id);
                        }}
                      >
                        Review Delta →
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
