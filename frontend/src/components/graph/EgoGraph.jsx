import React, { useEffect, useMemo, useState } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import { buildElements } from './buildElements';
import './EgoGraph.css';

const SHOW_TTPS_STORAGE_KEY = 'crossroads-show-ttps';

export function EgoGraph({ data, onNodeClick }) {
  // Defaults to hidden: TTPs are frequently the majority of a well-documented actor's
  // ego-graph neighbors (dozens of USES edges), crowding out the other entity types.
  const [showTtps, setShowTtps] = useState(() => localStorage.getItem(SHOW_TTPS_STORAGE_KEY) === 'true');

  useEffect(() => {
    localStorage.setItem(SHOW_TTPS_STORAGE_KEY, String(showTtps));
  }, [showTtps]);

  const elements = useMemo(
    () => buildElements(data, { hideTypes: showTtps ? [] : ['ttp'] }),
    [data, showTtps]
  );

  const stylesheet = [
    {
      selector: 'node',
      style: {
        'label': 'data(label)',
        'color': '#fff',
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': '10px',
        'text-wrap': 'ellipsis',
        'text-max-width': '80px',
        'width': '40px',
        'height': '40px',
      }
    },
    { selector: 'node[type="cve"]', style: { 'background-color': '#ef4444', 'shape': 'round-rectangle', 'width': '80px' } },
    { selector: 'node[type="threat_actor"], node[type="actor"]', style: { 'background-color': '#a855f7', 'shape': 'diamond' } },
    { selector: 'node[type="malware_family"], node[type="malware"]', style: { 'background-color': '#3b82f6', 'shape': 'hexagon' } },
    { selector: 'node[type="ttp"]', style: { 'background-color': '#22c55e', 'shape': 'triangle' } },
    { selector: 'node[type="ioc"]', style: { 'background-color': '#f97316', 'shape': 'ellipse' } },
    { selector: 'node[type="article"]', style: { 'background-color': '#6b7280', 'shape': 'ellipse' } },
    { selector: 'node[type="cwe"]', style: { 'background-color': '#eab308', 'shape': 'round-diamond' } },
    {
      selector: 'edge',
      style: {
        'width': 'mapData(confidence, 0, 1, 1, 4)',
        'line-color': '#475569',
        'target-arrow-color': '#475569',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '8px',
        'color': '#9ca3af',
        'text-rotation': 'autorotate'
      }
    },
    { selector: 'edge[origin="authoritative"]', style: { 'line-style': 'solid' } },
    { selector: 'edge[origin="inferred"]', style: { 'line-style': 'dashed' } },
  ];

  return (
    <div className="ego-graph card">
      <div className="ego-graph__header">
        <h3 className="panel-title">Relationship Graph</h3>
        <button
          type="button"
          className="btn btn--ghost btn--sm"
          onClick={() => setShowTtps((prev) => !prev)}
        >
          {showTtps ? 'Hide TTPs' : 'Show TTPs'}
        </button>
      </div>
      <div className="graph-container">
        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet}
          layout={{ name: 'cose', padding: 20, randomize: true }}
          style={{ width: '100%', height: '100%' }}
          cy={(cy) => {
            cy.on('tap', 'node', (evt) => {
              if (onNodeClick) onNodeClick(evt.target.data());
            });
          }}
        />
      </div>
    </div>
  );
}
