import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Search, 
  Users, 
  Grid3x3, 
  Star, 
  FileText, 
  Settings,
  Menu,
  Shield
} from 'lucide-react';
import { ThemeToggle } from '../common/ThemeToggle';
import './Sidebar.css';

export function Sidebar({ collapsed, setCollapsed }) {
  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/search', icon: Search, label: 'Search' },
    { to: '/threats', icon: ShieldAlert, label: 'Threats' },
    { to: '/actors', icon: Users, label: 'Actors' },
    { to: '/heatmap', icon: Grid3x3, label: 'Heatmap' },
    { to: '/watchlists', icon: Star, label: 'Watchlists' },
    { to: '/briefings', icon: FileText, label: 'Briefings' },
    { to: '/settings', icon: Settings, label: 'Settings' }
  ];

  return (
    <aside id="app-sidebar" className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="sidebar-brand">
          <Shield className="sidebar-brand-icon" size={28} />
          {!collapsed && <span className="sidebar-brand-text">Crossroads</span>}
        </div>
        <button 
          id="sidebar-toggle-btn"
          className="sidebar-toggle btn btn--ghost btn--sm" 
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <Menu size={20} />
        </button>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              id={`nav-link-${item.label.toLowerCase()}`}
              className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`}
              title={collapsed ? item.label : undefined}
            >
              <Icon size={20} />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <ThemeToggle />
      </div>
    </aside>
  );
}
