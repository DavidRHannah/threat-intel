import React, { useState, useMemo } from 'react';
import { AttackMatrix } from '../components/heatmap/AttackMatrix';
import { TechniqueDrawer } from '../components/heatmap/TechniqueDrawer';
import { mockTtpHeatmap } from '../api/mockData';
import './HeatmapPage.css';

export default function HeatmapPage() {
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [minHeat, setMinHeat] = useState(0.0);
  const [showActiveOnly, setShowActiveOnly] = useState(false);

  const filteredData = useMemo(() => {
    const tactics = mockTtpHeatmap.tactics;
    let techniques = mockTtpHeatmap.techniques;

    if (showActiveOnly) {
      techniques = techniques.filter(t => t.exploiter_count > 0);
    }
    techniques = techniques.filter(t => t.heat >= minHeat);

    return { tactics, techniques };
  }, [minHeat, showActiveOnly]);

  return (
    <div className="page-container heatmap-page fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">ATT&CK Heatmap</h1>
          <p className="page-description">Visualize tactic and technique coverage across threat actors and campaigns.</p>
        </div>
      </div>

      <div className="heatmap-controls card">
        <div className="control-group">
          <label htmlFor="heat-slider" className="control-label">Minimum Heat ({minHeat.toFixed(2)})</label>
          <input 
            type="range" 
            id="heat-slider" 
            min="0" 
            max="1" 
            step="0.05" 
            value={minHeat} 
            onChange={(e) => setMinHeat(parseFloat(e.target.value))}
            className="slider"
          />
        </div>
        <div className="control-group row-group">
          <input 
            type="checkbox" 
            id="active-toggle"
            checked={showActiveOnly}
            onChange={(e) => setShowActiveOnly(e.target.checked)}
          />
          <label htmlFor="active-toggle" className="control-label">Active Exploiters Only</label>
        </div>
      </div>

      <div className="matrix-wrapper">
        <AttackMatrix 
          data={filteredData} 
          onSelectTechnique={setSelectedTechnique}
        />
      </div>

      <TechniqueDrawer 
        technique={selectedTechnique} 
        onClose={() => setSelectedTechnique(null)} 
      />
    </div>
  );
}
