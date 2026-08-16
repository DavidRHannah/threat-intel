import React from 'react';
import { Link } from 'react-router-dom';
import { X, ExternalLink, Activity } from 'lucide-react';
import { EntityBadge } from '../common/EntityBadge';
import './TechniqueDrawer.css';

export function TechniqueDrawer({ technique, onClose }) {
  if (!technique) return null;

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} id="drawer-backdrop" />
      <div className="drawer-panel fade-in">
        <div className="drawer-header">
          <div>
            <div className="drawer-id">{technique.id}</div>
            <h2 className="drawer-title">{technique.name}</h2>
          </div>
          <button className="btn btn--ghost btn--sm" onClick={onClose} id="drawer-close-btn">
            <X size={24} />
          </button>
        </div>

        <div className="drawer-content">
          <div className="card drawer-stat-card">
            <div className="stat-label">
              <Activity size={16} />
              Heat Score
            </div>
            <div className="stat-value-row">
              <span className="stat-value">{technique.heat.toFixed(2)}</span>
              <div 
                className="heat-indicator"
                style={{
                  background: `linear-gradient(to right, #3b82f6, #eab308, #ef4444)`,
                  opacity: technique.heat
                }}
              ></div>
            </div>
          </div>

          <div className="drawer-section">
            <h3 className="section-title">Top Exploiters ({technique.exploiter_count})</h3>
            <ul className="exploiter-list">
              {technique.top_exploiters && technique.top_exploiters.map((exploiter) => (
                <li key={exploiter.id} className="exploiter-item">
                  <Link to={`/entity/${exploiter.type}/${exploiter.id}`} className="exploiter-link">
                    <EntityBadge type={exploiter.type} />
                    <span>{exploiter.name}</span>
                  </Link>
                </li>
              ))}
              {technique.top_exploiters?.length === 0 && (
                <li className="text-secondary">No known exploiters.</li>
              )}
            </ul>
          </div>

          <div className="drawer-actions">
            <a 
              href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}`} 
              target="_blank" 
              rel="noreferrer"
              className="btn btn--secondary"
            >
              <ExternalLink size={16} />
              View on MITRE ATT&CK
            </a>
          </div>
        </div>
      </div>
    </>
  );
}
