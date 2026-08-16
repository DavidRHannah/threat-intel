import React, { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { LayoutGrid, List, CheckCircle2, AlertTriangle } from 'lucide-react';
import { useTopActors, useTopMalware, useTopCampaigns } from '../api/hooks';
import { formatDate } from '../utils/formatters';
import './ActorsPage.css';

const TAB_CONFIG = {
  actors: {
    label: 'Threat Actors',
    entityType: 'actor',
    metaPrefix: 'Origin',
    metaValue: (item) => item.origin_country || 'Unknown',
  },
  malware: {
    label: 'Malware Families',
    entityType: 'malware',
    metaPrefix: 'Type',
    metaValue: (item) => item.malware_type || 'Unknown',
  },
  campaigns: {
    label: 'Campaigns',
    entityType: 'campaign',
    metaPrefix: 'Active',
    metaValue: (item) => `${formatDate(item.start_date)} – ${item.end_date ? formatDate(item.end_date) : 'present'}`,
  },
};

export default function ActorsPage() {
  const [searchParams] = useSearchParams();
  const initialTab = TAB_CONFIG[searchParams.get('tab')] ? searchParams.get('tab') : 'actors';
  const [activeTab, setActiveTab] = useState(initialTab);
  const [viewMode, setViewMode] = useState('grid');
  const [sortBy, setSortBy] = useState('relevance');
  const { data: actorsData } = useTopActors(100);
  const { data: malwareData } = useTopMalware(100);
  const { data: campaignsData } = useTopCampaigns(100);

  const dataByTab = {
    actors: actorsData?.actors,
    malware: malwareData?.malware,
    campaigns: campaignsData?.campaigns,
  };
  const tab = TAB_CONFIG[activeTab];
  const data = dataByTab[activeTab] ?? [];
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
          {Object.entries(TAB_CONFIG).map(([id, config]) => (
            <button
              key={id}
              id={`tab-${id}`}
              className={`tab ${activeTab === id ? 'active' : ''}`}
              onClick={() => setActiveTab(id)}
            >
              {config.label}
            </button>
          ))}
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
              <Link to={`/entity/${tab.entityType}/${item.id}`} key={item.id} className="actor-card card card--clickable">
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
                  <span className="meta-badge">{tab.metaPrefix}: {tab.metaValue(item)}</span>
                </div>
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
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {sortedData.map(item => (
                  <tr key={item.id}>
                    <td>
                      <Link to={`/entity/${tab.entityType}/${item.id}`}>{item.name}</Link>
                    </td>
                    <td>{item.mitre_id || '—'}</td>
                    <td>{tab.metaValue(item)}</td>
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
