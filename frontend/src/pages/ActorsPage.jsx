import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { LayoutGrid, List, CheckCircle2, AlertTriangle } from 'lucide-react';
import { useTopActors, useTopMalware } from '../api/hooks';
import { formatScore } from '../utils/formatters';
import './ActorsPage.css';

export default function ActorsPage() {
  const [activeTab, setActiveTab] = useState('actors');
  const [viewMode, setViewMode] = useState('grid');
  const [sortBy, setSortBy] = useState('relevance');
  const { data: actorsData } = useTopActors(100);
  const { data: malwareData } = useTopMalware(100);

  const data = activeTab === 'actors' ? (actorsData?.actors ?? []) : (malwareData?.malware ?? []);
  const sortedData = [...data].sort((a, b) => {
    if (sortBy === 'relevance') return (b.relevance_score || 0) - (a.relevance_score || 0);
    if (sortBy === 'name') return a.name.localeCompare(b.name);
    if (sortBy === 'confidence') return (b.confidence || 0) - (a.confidence || 0);
    return 0;
  });

  return (
    <div className="actors-page fade-in">
      <div className="actors-header">
        <div className="tabs">
          <button 
            id="tab-actors"
            className={`tab ${activeTab === 'actors' ? 'active' : ''}`}
            onClick={() => setActiveTab('actors')}
          >
            Threat Actors
          </button>
          <button 
            id="tab-malware"
            className={`tab ${activeTab === 'malware' ? 'active' : ''}`}
            onClick={() => setActiveTab('malware')}
          >
            Malware Families
          </button>
        </div>
        
        <div className="controls">
          <select 
            id="sort-select"
            value={sortBy} 
            onChange={(e) => setSortBy(e.target.value)}
            className="sort-select"
          >
            <option value="relevance">By Relevance</option>
            <option value="name">By Name</option>
            <option value="confidence">By Confidence</option>
          </select>
          
          <div className="view-toggle">
            <button 
              id="view-grid"
              className={`btn btn--ghost ${viewMode === 'grid' ? 'active' : ''}`}
              onClick={() => setViewMode('grid')}
            >
              <LayoutGrid size={20} />
            </button>
            <button 
              id="view-list"
              className={`btn btn--ghost ${viewMode === 'list' ? 'active' : ''}`}
              onClick={() => setViewMode('list')}
            >
              <List size={20} />
            </button>
          </div>
        </div>
      </div>

      <div className={`actors-content ${viewMode}`}>
        {viewMode === 'grid' ? (
          <div className="actors-grid">
            {sortedData.map(item => (
              <Link to={`/entity/${activeTab === 'actors' ? 'actor' : 'malware'}/${item.id}`} key={item.id} className="actor-card card card--clickable">
                <div className="actor-card-header">
                  <h3 className="actor-name">{item.name}</h3>
                  {item.confidence === 1.0 ? (
                    <CheckCircle2 size={16} className="confidence-icon high" />
                  ) : (
                    <AlertTriangle size={16} className="confidence-icon medium" />
                  )}
                </div>
                {item.mitre_id && <span className="actor-alias">{item.mitre_id}</span>}
                
                <div className="actor-meta">
                  {activeTab === 'actors' ? (
                    <span className="meta-badge">Origin: {item.origin_country}</span>
                  ) : (
                    <span className="meta-badge">Type: {item.malware_type}</span>
                  )}
                </div>

                <div className="relevance-bar">
                  <div className="relevance-fill" style={{ width: `${item.relevance_score * 100}%` }}></div>
                </div>
                <div className="relevance-label">Relevance: {formatScore(item.relevance_score)}</div>
              </Link>
            ))}
          </div>
        ) : (
          <div className="actors-list card">
            <table className="list-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>ID</th>
                  <th>Metadata</th>
                  <th>Relevance</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {sortedData.map(item => (
                  <tr key={item.id}>
                    <td>
                      <Link to={`/entity/${activeTab === 'actors' ? 'actor' : 'malware'}/${item.id}`}>{item.name}</Link>
                    </td>
                    <td>{item.mitre_id || '—'}</td>
                    <td>{activeTab === 'actors' ? item.origin_country : item.malware_type}</td>
                    <td>{formatScore(item.relevance_score)}</td>
                    <td>{item.confidence === 1.0 ? 'High' : 'Provisional'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
