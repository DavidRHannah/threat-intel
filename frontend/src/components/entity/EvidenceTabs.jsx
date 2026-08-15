import React, { useState } from 'react';
import './EvidenceTabs.css';

export function EvidenceTabs({ subgraph }) {
  const [activeTab, setActiveTab] = useState('articles');
  
  if (!subgraph) return null;

  const { neighbors, edges } = subgraph;

  const getNeighborsByType = (typeGroup) => {
    return neighbors.filter(n => typeGroup.includes(n.type));
  };

  const articles = getNeighborsByType(['article']);
  const actors = getNeighborsByType(['threat_actor', 'actor']);
  const ttps = getNeighborsByType(['ttp']);
  const iocs = getNeighborsByType(['ioc']);

  return (
    <div className="evidence-tabs card">
      <div className="tabs-header">
        {['articles', 'actors', 'ttps', 'iocs'].map(tab => (
          <button 
            key={tab}
            id={`tab-${tab}`}
            className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'articles' && 'Related Articles'}
            {tab === 'actors' && 'Exploiting Actors'}
            {tab === 'ttps' && 'Associated TTPs'}
            {tab === 'iocs' && 'IOC Indicators'}
          </button>
        ))}
        <div className={`tab-indicator indicator-${activeTab}`}></div>
      </div>

      <div className="tab-content">
        {activeTab === 'articles' && (
          <table className="evidence-table">
            <thead><tr><th>Title</th><th>Source</th></tr></thead>
            <tbody>
              {/* Article nodes carry `source_id`; `source` is the mock-data name. */}
              {articles.map(n => <tr key={n.id}><td>{n.title}</td><td>{n.source || n.source_id}</td></tr>)}
              {articles.length === 0 && <tr><td colSpan="2">No related articles found.</td></tr>}
            </tbody>
          </table>
        )}

        {activeTab === 'actors' && (
          <table className="evidence-table">
            <thead><tr><th>Name</th><th>Confidence</th><th>Origin</th></tr></thead>
            <tbody>
              {actors.map(n => {
                const edge = edges.find(e => e.target === n.id || e.source === n.id);
                return (
                  <tr key={n.id}>
                    <td>{n.name}</td>
                    <td>{edge?.confidence ? (edge.confidence * 100).toFixed(0) + '%' : 'N/A'}</td>
                    <td>
                      {edge?.origin?.map((orig, i) => (
                         <span key={i} className="badge badge--unknown" style={{ marginRight: '4px' }}>{orig}</span>
                      ))}
                    </td>
                  </tr>
                );
              })}
              {actors.length === 0 && <tr><td colSpan="3">No exploiting actors found.</td></tr>}
            </tbody>
          </table>
        )}

        {activeTab === 'ttps' && (
          <table className="evidence-table">
            <thead><tr><th>MITRE ID</th><th>Name</th><th>Tactic</th></tr></thead>
            <tbody>
              {ttps.map(n => (
                <tr key={n.id}>
                  <td>{n.mitre_id}</td>
                  <td>{n.name}</td>
                  <td>{n.tactic}</td>
                </tr>
              ))}
              {ttps.length === 0 && <tr><td colSpan="3">No associated TTPs found.</td></tr>}
            </tbody>
          </table>
        )}

        {activeTab === 'iocs' && (
          <table className="evidence-table">
            <thead><tr><th>Value</th><th>Type</th></tr></thead>
            <tbody>
              {iocs.map(n => (
                <tr key={n.id}>
                  <td>{n.value}</td>
                  <td><span className="badge badge--ioc">{n.ioc_type}</span></td>
                </tr>
              ))}
              {iocs.length === 0 && <tr><td colSpan="2">No IOC indicators found.</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
