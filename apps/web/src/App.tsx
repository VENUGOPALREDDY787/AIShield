import React, { useEffect, useState } from 'react';
import { Header } from './components/common/Header.js';
import { DashboardPage } from './pages/DashboardPage.js';
import { RepositoryPage } from './pages/RepositoryPage.js';
import { PullRequestPage } from './pages/PullRequestPage.js';
import { ScanDetailsPage } from './pages/ScanDetailsPage.js';
import { FindingDetailsPage } from './pages/FindingDetailsPage.js';
import { DebtHistoryPage } from './pages/DebtHistoryPage.js';
import { fetchHealth, getDemoMode, setDemoMode } from './services/api.js';
import type { PageRoute } from './types/index.js';
import './App.css';

function parseHashRoute(): PageRoute {
  const hash = window.location.hash.slice(1);
  if (!hash) return { name: 'dashboard' };

  const [path, queryString] = hash.split('?');
  const params = new URLSearchParams(queryString || '');

  if (path === 'repositories' || path === 'repository') {
    return { name: 'repository', repoId: params.get('id') || undefined };
  }
  if (path === 'pull-request' || path === 'pr') {
    return { name: 'pull-request', prId: params.get('id') || 'pr-42' };
  }
  if (path === 'scan' || path === 'scan-details') {
    return { name: 'scan-details', scanId: params.get('id') || 'scan-20260926-001' };
  }
  if (path === 'finding' || path === 'finding-details') {
    return { name: 'finding-details', findingId: params.get('id') || 'finding-001' };
  }
  if (path === 'history' || path === 'debt-history') {
    return { name: 'debt-history', repoId: params.get('id') || undefined };
  }

  return { name: 'dashboard' };
}

function routeToHash(route: PageRoute): string {
  switch (route.name) {
    case 'dashboard':
      return '#dashboard';
    case 'repository':
      return route.repoId ? `#repository?id=${route.repoId}` : '#repository';
    case 'pull-request':
      return `#pull-request?id=${route.prId}`;
    case 'scan-details':
      return `#scan?id=${route.scanId}`;
    case 'finding-details':
      return `#finding?id=${route.findingId}`;
    case 'debt-history':
      return route.repoId ? `#history?id=${route.repoId}` : '#history';
    default:
      return '#dashboard';
  }
}

export const App: React.FC = () => {
  const [currentRoute, setCurrentRoute] = useState<PageRoute>(parseHashRoute());
  const [apiStatus, setApiStatus] = useState<'ok' | 'error' | 'loading'>('loading');
  const [uptimeSeconds, setUptimeSeconds] = useState<number | undefined>();
  const [isDemo, setIsDemo] = useState<boolean>(getDemoMode());

  useEffect(() => {
    fetchHealth()
      .then((data) => {
        setApiStatus(data.status === 'ok' ? 'ok' : 'error');
        setUptimeSeconds(data.uptimeSeconds);
      })
      .catch(() => {
        setApiStatus('error');
      });

    const handleHashChange = () => {
      setCurrentRoute(parseHashRoute());
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleNavigate = (route: PageRoute) => {
    setCurrentRoute(route);
    window.location.hash = routeToHash(route);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleToggleDemo = (enabled: boolean) => {
    setDemoMode(enabled);
    setIsDemo(enabled);
  };

  return (
    <div className="dashboard-container">
      <Header
        apiStatus={apiStatus}
        uptimeSeconds={uptimeSeconds}
        currentRoute={currentRoute}
        onRouteChange={handleNavigate}
        isDemoMode={isDemo}
        onToggleDemoMode={handleToggleDemo}
      />

      <main className="dashboard-main">
        {currentRoute.name === 'dashboard' && <DashboardPage onNavigate={handleNavigate} />}
        {currentRoute.name === 'repository' && (
          <RepositoryPage repoId={currentRoute.repoId} onNavigate={handleNavigate} />
        )}
        {currentRoute.name === 'pull-request' && (
          <PullRequestPage prId={currentRoute.prId} onNavigate={handleNavigate} />
        )}
        {currentRoute.name === 'scan-details' && (
          <ScanDetailsPage scanId={currentRoute.scanId} onNavigate={handleNavigate} />
        )}
        {currentRoute.name === 'finding-details' && (
          <FindingDetailsPage findingId={currentRoute.findingId} onNavigate={handleNavigate} />
        )}
        {currentRoute.name === 'debt-history' && (
          <DebtHistoryPage repoId={currentRoute.repoId} onNavigate={handleNavigate} />
        )}
      </main>
    </div>
  );
};

export default App;
