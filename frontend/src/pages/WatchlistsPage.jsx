import React, { useState } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { mockWatchlists } from '../api/mockData';
import { formatDate } from '../utils/formatters';
import './WatchlistsPage.css';

export default function WatchlistsPage() {
  const [selectedId, setSelectedId] = useState(null);
  
  const selectedWatchlist = mockWatchlists.find(w => w.watchlist_id === selectedId);

  return (
    <div className="watchlists-page fade-in">
      <div className="watchlists-sidebar">
        <div className="sidebar-header">
          <h2>Watchlists</h2>
          <button id="btn-new-watchlist" className="btn btn--primary btn--sm">
            <Plus size={16} /> New
          </button>
        </div>
        
        <div className="watchlist-cards">
          {mockWatchlists.map(w => (
            <div 
              key={w.watchlist_id} 
              id={`watchlist-${w.watchlist_id}`}
              className={`watchlist-card card card--clickable ${selectedId === w.watchlist_id ? 'active' : ''}`}
              onClick={() => setSelectedId(w.watchlist_id)}
            >
              <h4>{w.name}</h4>
              <div className="watchlist-meta">
                <span>{w.selectors.length} selectors</span>
                <span>{w.routes.length} routes</span>
              </div>
              <div className="watchlist-date">Updated: {formatDate(w.updated_at)}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="watchlists-detail">
        {!selectedWatchlist ? (
          <div className="empty-state">
            <p>Select a watchlist or create a new one</p>
          </div>
        ) : (
          <div className="detail-form card">
            <div className="form-group">
              <label htmlFor="wl-name">Watchlist Name</label>
              <input id="wl-name" type="text" defaultValue={selectedWatchlist.name} />
            </div>

            <div className="form-section">
              <h3>Selectors</h3>
              <div className="selectors-list">
                {selectedWatchlist.selectors.map((sel, idx) => (
                  <div key={idx} className="selector-row">
                    <select id={`sel-type-${idx}`} defaultValue={sel.type}>
                      <option value="cve">CVE</option>
                      <option value="actor">Actor</option>
                      <option value="ttp">TTP</option>
                      <option value="product">Product</option>
                      <option value="ioc">IOC</option>
                    </select>
                    <input type="text" id={`sel-val-${idx}`} defaultValue={sel.name || sel.mitre_id || sel.pattern} className="selector-input" />
                    <button className="btn btn--ghost"><Trash2 size={16}/></button>
                  </div>
                ))}
              </div>
              <button id="add-selector" className="btn btn--secondary btn--sm"><Plus size={16}/> Add Selector</button>
            </div>

            <div className="form-section">
              <h3>Boost Value</h3>
              <div className="form-group">
                <input id="wl-boost" type="number" step="0.1" defaultValue={selectedWatchlist.boost} />
                <span className="help-text">Multiplier for relevance score (e.g. 1.5)</span>
              </div>
            </div>

            <div className="form-section">
              <h3>Alert Thresholds</h3>
              <div className="threshold-row">
                <label>Severity {'>='}</label>
                <input type="range" min="0" max="1" step="0.1" defaultValue={selectedWatchlist.alert_thresholds.severity_gte || 0} />
              </div>
              <div className="threshold-row">
                <label>Relevance {'>='}</label>
                <input type="range" min="0" max="1" step="0.1" defaultValue={selectedWatchlist.alert_thresholds.relevance_gte || 0} />
              </div>
              <label className="checkbox-label">
                <input type="checkbox" id="wl-kev" defaultChecked={selectedWatchlist.alert_thresholds.kev_listed} />
                KEV Listed
              </label>
            </div>

            <div className="form-section">
              <h3>Notification Routes</h3>
              <div className="routes-list">
                {selectedWatchlist.routes.map((route, idx) => (
                  <div key={idx} className="route-row">
                    <select id={`route-chan-${idx}`} defaultValue={route.channel}>
                      <option value="slack">Slack</option>
                      <option value="teams">Teams</option>
                      <option value="webhook">Webhook</option>
                    </select>
                    <input type="text" id={`route-url-${idx}`} defaultValue={route.webhook_url || route.url} className="route-input" />
                    <button className="btn btn--ghost"><Trash2 size={16}/></button>
                  </div>
                ))}
              </div>
              <button id="add-route" className="btn btn--secondary btn--sm"><Plus size={16}/> Add Route</button>
            </div>

            <div className="form-actions">
              <button id="save-wl" className="btn btn--primary">Save Changes</button>
              <button id="del-wl" className="btn btn--secondary" style={{color: 'var(--color-critical)'}}>Delete</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
