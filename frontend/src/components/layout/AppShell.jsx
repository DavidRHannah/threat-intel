import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import './AppShell.css';

/* Maps route paths to page titles shown in the Header */
const PAGE_TITLES = {
  '/': 'Dashboard',
  '/search': 'Search',
  '/threats': 'Threats',
  '/actors': 'Actors & Malware',
  '/heatmap': 'ATT&CK Heatmap',
  '/watchlists': 'Watchlists',
  '/briefings': 'Briefings',
  '/settings': 'Settings',
};

export function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const { pathname } = useLocation();

  const pageTitle = PAGE_TITLES[pathname] || 'Entity Detail';

  return (
    <div className={`app-shell ${sidebarCollapsed ? 'app-shell--collapsed' : ''}`}>
      <Sidebar collapsed={sidebarCollapsed} setCollapsed={setSidebarCollapsed} />

      <div className="app-shell-main">
        <Header title={pageTitle} collapsed={sidebarCollapsed} />

        <main className="app-shell-content">
          <div className="app-shell-content-inner">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
