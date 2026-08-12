import { Search, Bell, User } from 'lucide-react';
import './Header.css';

export function Header({ title, collapsed }) {
  return (
    <header className="app-header">
      <div className="app-header-left">
        <h1 className="app-header-title">{title}</h1>
      </div>
      
      <div className="app-header-center">
        <div className="app-search-container">
          <Search className="app-search-icon" size={18} />
          <input 
            type="text" 
            id="global-search-input"
            className="app-search-input" 
            placeholder="Search threats, CVEs, actors..." 
          />
        </div>
      </div>
      
      <div className="app-header-right">
        <button id="notification-btn" className="btn btn--ghost header-btn" title="Notifications">
          <Bell size={20} />
          <span className="notification-badge">3</span>
        </button>
        <button id="user-profile-btn" className="user-avatar-btn" title="User Profile">
          <div className="user-avatar">
            DH
          </div>
        </button>
      </div>
    </header>
  );
}
