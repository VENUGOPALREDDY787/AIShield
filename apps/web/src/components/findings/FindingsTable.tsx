import React, { useState } from 'react';
import type { DisplayFinding } from '../../types/index.js';
import { Badge } from '../common/Badge.js';

interface FindingsTableProps {
  findings: DisplayFinding[];
  onSelectFinding?: (findingId: string) => void;
  title?: string;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
  title = 'Security Findings & Weaknesses',
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filtered = findings.filter((f) => {
    if (severityFilter !== 'all' && f.severity.toUpperCase() !== severityFilter.toUpperCase()) {
      return false;
    }
    if (categoryFilter !== 'all' && f.category !== categoryFilter) {
      return false;
    }
    if (searchTerm.trim().length > 0) {
      const q = searchTerm.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.filePath.toLowerCase().includes(q) ||
        (f.description && f.description.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const uniqueCategories = Array.from(new Set(findings.map((f) => f.category))).filter(Boolean);

  return (
    <div className="card findings-card">
      <div className="card-header">
        <div>
          <h3>{title}</h3>
          <span className="count-pill">{filtered.length} of {findings.length} findings</span>
        </div>

        <div className="table-filters">
          <input
            type="text"
            className="filter-input"
            placeholder="Search by file or title..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />

          <select
            className="filter-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {uniqueCategories.length > 1 && (
            <select
              className="filter-select"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
            >
              <option value="all">All Categories</option>
              {uniqueCategories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      <div className="table-responsive">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Source</th>
              <th>Category</th>
              <th>Vulnerability / Title</th>
              <th>Location</th>
              <th>Confidence</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="empty-state">
                  No matching security findings found.
                </td>
              </tr>
            ) : (
              filtered.map((f) => (
                <tr
                  key={f.id}
                  className="clickable-row"
                  onClick={() => onSelectFinding?.(f.id)}
                >
                  <td>
                    <Badge label={f.severity.toUpperCase()} variant={f.severity} />
                  </td>
                  <td>
                    <span className="scanner-tag">{f.source}</span>
                  </td>
                  <td>
                    <span className="category-tag">{f.category}</span>
                  </td>
                  <td className="finding-title">
                    <strong>{f.title}</strong>
                    {f.isNewInPr && <span className="tag-new">PR INTRODUCED</span>}
                    {f.remediation?.summary && (
                      <p className="remediation-hint">💡 {f.remediation.summary}</p>
                    )}
                  </td>
                  <td className="location-cell">
                    <code>
                      {f.filePath}:{f.line}
                    </code>
                  </td>
                  <td>
                    <span className="confidence-pill">
                      {Math.round((f.confidence ?? 1.0) * 100)}%
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn-link"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding?.(f.id);
                      }}
                    >
                      Inspect →
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
