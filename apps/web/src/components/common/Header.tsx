import React from 'react';
import type { PageRoute } from '../../types/index.js';

interface HeaderProps {
  apiStatus: 'ok' | 'error' | 'loading';
  uptimeSeconds?: number;
  currentRoute: PageRoute;
  onRouteChange: (route: PageRoute) => void;
  isDemoMode: boolean;
  onToggleDemoMode: (enabled: boolean) => void;
}

export const Header: React.FC<HeaderProps> = ({
  apiStatus,
  uptimeSeconds,
  currentRoute,
  onRouteChange,
  isDemoMode,
  onToggleDemoMode,
}) => {
  return (
    <header className="app-header">
      <div className="header-left">
        <div className="brand" onClick={() => onRouteChange({ name: 'dashboard' })} style={{ cursor: 'pointer' }}>
          <span className="logo-icon">🛡️</span>
          <div>
            <h1 className="brand-title">AIShield Debt</h1>
            <p className="brand-subtitle">AI-Assisted Code Security & Technical Debt</p>
          </div>
        </div>

        <nav className="header-nav">
          <button
            className={`nav-link ${currentRoute.name === 'dashboard' ? 'active' : ''}`}
            onClick={() => onRouteChange({ name: 'dashboard' })}
          >
            Dashboard
          </button>
          <button
            className={`nav-link ${currentRoute.name === 'repository' ? 'active' : ''}`}
            onClick={() => onRouteChange({ name: 'repository' })}
          >
            Repositories
          </button>
          <button
            className={`nav-link ${currentRoute.name === 'debt-history' ? 'active' : ''}`}
            onClick={() => onRouteChange({ name: 'debt-history' })}
          >
            Debt History
          </button>
        </nav>
      </div>

      <div className="header-right">
        <div className="demo-toggle-container">
          <label className="toggle-label" title="Toggle isolated mock dataset for preview">
            <input
              type="checkbox"
              checked={isDemoMode}
              onChange={(e) => onToggleDemoMode(e.target.checked)}
            />
            <span className="toggle-text">{isDemoMode ? 'Demo Mode: ON' : 'Live API'}</span>
          </label>
        </div>

        <div className="system-status">
          <span className={`status-pill ${isDemoMode ? 'demo' : apiStatus}`}>
            <span className="status-dot"></span>
            {isDemoMode ? 'DEMO' : `API: ${apiStatus.toUpperCase()}`}
          </span>
          {uptimeSeconds !== undefined && !isDemoMode && (
            <span className="uptime-text">Uptime: {uptimeSeconds}s</span>
          )}
        </div>
      </div>
    </header>
  );
};
