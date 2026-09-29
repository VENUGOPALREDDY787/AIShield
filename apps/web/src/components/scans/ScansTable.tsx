import React from 'react';
import type { ScanDetails } from '../../types/index.js';
import { Badge } from '../common/Badge.js';

interface ScansTableProps {
  scans: ScanDetails[];
  onSelectScan?: (scanId: string) => void;
}

export const ScansTable: React.FC<ScansTableProps> = ({ scans, onSelectScan }) => {
  return (
    <div className="card scans-card">
      <div className="card-header">
        <div>
          <h3>Recent Security Scans</h3>
          <span className="info-tooltip">Multi-Scanner Pipeline Executions</span>
        </div>
        <span className="count-pill">{scans.length} scans</span>
      </div>

      <div className="table-responsive">
        <table className="data-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Commit / Branch</th>
              <th>Trigger</th>
              <th>Components Status</th>
              <th>Score Result</th>
              <th>Findings Summary</th>
              <th>Duration</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 ? (
              <tr>
                <td colSpan={8} className="empty-state">
                  No scans recorded yet.
                </td>
              </tr>
            ) : (
              scans.map((scan) => (
                <tr
                  key={scan.id}
                  className="clickable-row"
                  onClick={() => onSelectScan?.(scan.id)}
                >
                  <td>
                    <Badge label={scan.status.toUpperCase()} variant={scan.status} size="sm" />
                  </td>
                  <td>
                    <div className="commit-cell">
                      <code>{scan.commitSha?.slice(0, 7) || 'HEAD'}</code>
                      <span className="branch-label">{scan.branch}</span>
                    </div>
                  </td>
                  <td>
                    <span className="category-tag">{scan.trigger}</span>
                  </td>
                  <td>
                    <div className="component-badges-row">
                      {scan.components?.map((c) => (
                        <span
                          key={c.source}
                          className={`component-pill ${c.status}`}
                          title={`${c.source}: ${c.status} (${c.findingCount} findings)`}
                        >
                          {c.source.slice(0, 4).toUpperCase()}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    {scan.score !== undefined ? (
                      <span className="score-result-badge">
                        <strong>{Math.round(scan.score)}</strong>/100 (Grade {scan.grade})
                      </span>
                    ) : (
                      <span className="text-muted">-</span>
                    )}
                  </td>
                  <td>
                    <span className="findings-count-badge">
                      {scan.summary?.totalFindings || 0} issues
                    </span>
                  </td>
                  <td>
                    <span className="duration-text">
                      {scan.durationMs ? `${Math.round(scan.durationMs / 1000)}s` : '-'}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn-link"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectScan?.(scan.id);
                      }}
                    >
                      View Report →
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
