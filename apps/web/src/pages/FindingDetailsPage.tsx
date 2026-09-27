import React, { useEffect, useState } from 'react';
import { Badge } from '../components/common/Badge.js';
import { fetchFindingById } from '../services/api.js';
import type { DisplayFinding, PageRoute } from '../types/index.js';

interface FindingDetailsPageProps {
  findingId: string;
  onNavigate: (route: PageRoute) => void;
}

export const FindingDetailsPage: React.FC<FindingDetailsPageProps> = ({ findingId, onNavigate }) => {
  const [loading, setLoading] = useState(true);
  const [finding, setFinding] = useState<DisplayFinding | null>(null);

  useEffect(() => {
    async function loadFinding() {
      setLoading(true);
      try {
        const data = await fetchFindingById(findingId);
        setFinding(data);
      } catch (err) {
        console.error('Failed to load finding details:', err);
      } finally {
        setLoading(false);
      }
    }

    loadFinding();
  }, [findingId]);

  if (loading || !finding) {
    return (
      <div className="page-content loading-state">
        <div className="spinner"></div>
        <p>Loading security finding details...</p>
      </div>
    );
  }

  return (
    <div className="page-content">
      {/* Breadcrumbs */}
      <div className="breadcrumb-nav">
        <button className="breadcrumb-link" onClick={() => onNavigate({ name: 'dashboard' })}>
          Dashboard
        </button>
        <span className="breadcrumb-separator">/</span>
        <button
          className="breadcrumb-link"
          onClick={() => onNavigate({ name: 'repository', repoId: finding.repositoryId })}
        >
          Repository Findings
        </button>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-current">{finding.cwe || finding.fingerprint.slice(0, 12)}</span>
      </div>

      {/* Finding Hero Card */}
      <div className="card finding-hero-card">
        <div className="finding-hero-header">
          <div className="finding-meta-badges">
            <Badge label={finding.severity.toUpperCase()} variant={finding.severity} />
            <span className="category-tag">{finding.category.toUpperCase()}</span>
            <span className="scanner-tag">Source: {finding.source}</span>
            {finding.cwe && <span className="cwe-tag">{finding.cwe}</span>}
            {finding.owasp && <span className="owasp-tag">{finding.owasp}</span>}
          </div>

          <div className="confidence-meter-box">
            <span className="meter-label">Detection Confidence</span>
            <div className="confidence-gauge">
              <span className="confidence-val">{Math.round((finding.confidence ?? 1.0) * 100)}%</span>
            </div>
          </div>
        </div>

        <h2 className="finding-title-hero">{finding.title}</h2>

        {finding.description && (
          <p className="finding-description-text">{finding.description}</p>
        )}

        <div className="finding-location-bar">
          <span className="loc-label">AFFECTED FILE:</span>
          <code className="loc-path">{finding.filePath}</code>
          <span className="loc-line">
            Line {finding.line}
            {finding.endLine && finding.endLine !== finding.line ? `–${finding.endLine}` : ''}
          </span>
          {finding.timesDetected > 1 && (
            <span className="recurrence-badge">Seen in {finding.timesDetected} scans</span>
          )}
        </div>
      </div>

      {/* Evidence Code Snippet Box */}
      {finding.snippet && (
        <div className="card section-block code-evidence-card">
          <div className="card-header">
            <h3>Code Evidence & Context</h3>
            {finding.snippetRedacted && (
              <span className="badge badge-warning">Secrets Redacted</span>
            )}
          </div>
          <pre className="code-block">
            <code>{finding.snippet}</code>
          </pre>
        </div>
      )}

      {/* AI Contextual Risk Assessment Card */}
      {finding.aiAnalysis && (
        <div className="card section-block ai-analysis-card">
          <div className="card-header">
            <div className="ai-header-title">
              <span className="ai-icon">🧠</span>
              <h3>AI Contextual Risk Analysis</h3>
            </div>
            <span className="badge badge-info">Gemini Context Engine</span>
          </div>

          <div className="ai-stats-row">
            <div className="ai-stat-box">
              <span className="stat-label">Exploitability</span>
              <span className={`stat-val exploit-${finding.aiAnalysis.exploitability || 'medium'}`}>
                {(finding.aiAnalysis.exploitability || 'medium').toUpperCase()}
              </span>
            </div>
            <div className="ai-stat-box">
              <span className="stat-label">Reachability</span>
              <span className="stat-val">
                {(finding.aiAnalysis.reachability || 'reachable').toUpperCase()}
              </span>
            </div>
            <div className="ai-stat-box">
              <span className="stat-label">False Positive Risk</span>
              <span className="stat-val">
                {Math.round((finding.aiAnalysis.falsePositiveLikelihood ?? 0.05) * 100)}%
              </span>
            </div>
          </div>

          {finding.aiAnalysis.summary && (
            <div className="ai-summary-block">
              <strong>Context Assessment:</strong>
              <p>{finding.aiAnalysis.summary}</p>
            </div>
          )}

          {finding.aiAnalysis.businessImpact && (
            <div className="ai-impact-block">
              <strong>Business & Data Impact:</strong>
              <p>{finding.aiAnalysis.businessImpact}</p>
            </div>
          )}
        </div>
      )}

      {/* Remediation Guide & Patch Card */}
      {finding.remediation && (
        <div className="card section-block remediation-card">
          <div className="card-header">
            <h3>Remediation Guidance & Suggested Fix</h3>
            <span className="badge badge-success">
              Effort: {(finding.remediation.effort || 'small').toUpperCase()}
            </span>
          </div>

          {finding.remediation.summary && (
            <p className="remediation-summary-text">{finding.remediation.summary}</p>
          )}

          {finding.remediation.steps && finding.remediation.steps.length > 0 && (
            <div className="remediation-steps-list">
              <h4>Recommended Steps:</h4>
              <ol>
                {finding.remediation.steps.map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))}
              </ol>
            </div>
          )}

          {finding.remediation.suggestedPatch && (
            <div className="suggested-patch-container">
              <h4>Suggested Patch Diff:</h4>
              <pre className="patch-code-block">
                <code>{finding.remediation.suggestedPatch}</code>
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
