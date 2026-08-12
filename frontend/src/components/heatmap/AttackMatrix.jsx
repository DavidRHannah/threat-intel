import React, { useMemo } from 'react';
import * as d3 from 'd3';
import './AttackMatrix.css';

export function AttackMatrix({ data, onSelectTechnique }) {
  const { tactics, techniques } = data;

  // Custom color scale: blue -> amber -> red
  const colorScale = d3.scaleLinear()
    .domain([0, 0.5, 1])
    .range(['#3b82f6', '#eab308', '#ef4444'])
    .clamp(true);

  return (
    <div className="attack-matrix-container">
      <div className="attack-matrix" style={{ gridTemplateColumns: `repeat(${tactics.length}, 1fr)` }}>
        {tactics.map(tactic => {
          const tacticTechniques = techniques.filter(t => t.tactic === tactic.id);
          return (
            <div key={tactic.id} className="tactic-column">
              <div className="tactic-header">
                <div className="tactic-name truncate" title={tactic.name}>{tactic.name}</div>
                <div className="tactic-id">{tactic.id}</div>
              </div>
              <div className="technique-list">
                {tacticTechniques.map(tech => (
                  <button 
                    key={tech.id} 
                    id={`tech-cell-${tech.id}`}
                    className="technique-cell"
                    style={{ backgroundColor: colorScale(tech.heat) }}
                    onClick={() => onSelectTechnique(tech)}
                  >
                    <div className="technique-cell-header">
                      <span className="technique-id">{tech.id}</span>
                    </div>
                    <div className="technique-name">{tech.name}</div>
                    
                    <div className="technique-tooltip">
                      <div className="tooltip-title">{tech.name} ({tech.id})</div>
                      <div className="tooltip-stat">Heat Score: {tech.heat.toFixed(2)}</div>
                      <div className="tooltip-stat">Exploiters: {tech.exploiter_count}</div>
                      {tech.top_exploiters && tech.top_exploiters.length > 0 && (
                        <div className="tooltip-exploiters">
                          Top: {tech.top_exploiters.join(', ')}
                        </div>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
      <div className="matrix-legend">
        <span className="legend-label">Cool (0.0)</span>
        <div className="legend-bar"></div>
        <span className="legend-label">Hot (1.0)</span>
      </div>
    </div>
  );
}
