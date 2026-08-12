import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import './MiniHeatmap.css';
import { mockTtpHeatmap } from '../../api/mockData';

export function MiniHeatmap() {
  // Sort by heat and take top 10
  const topTtps = [...mockTtpHeatmap.techniques]
    .sort((a, b) => b.heat - a.heat)
    .slice(0, 10);

  // Helper to determine color based on heat score (0-1)
  const getHeatColor = (heat) => {
    if (heat > 0.8) return 'var(--color-critical)';
    if (heat > 0.6) return 'var(--color-high)';
    if (heat > 0.4) return 'var(--color-medium)';
    return 'var(--color-primary)';
  };

  return (
    <div className="mini-heatmap card fade-in" id="mini-heatmap">
      <div className="mini-heatmap__header">
        <h2 className="mini-heatmap__title">ATT&CK Heatmap</h2>
        <Link to="/heatmap" className="mini-heatmap__link" id="link-full-heatmap">
          View Full <ArrowRight size={14} />
        </Link>
      </div>
      
      <div className="mini-heatmap__grid">
        {topTtps.map((ttp) => (
          <div 
            key={ttp.id}
            className="mini-heatmap__cell"
            style={{ backgroundColor: getHeatColor(ttp.heat) }}
            title={`${ttp.id}: ${ttp.name} (Heat: ${ttp.heat})`}
            id={`mini-heatmap-cell-${ttp.id}`}
          />
        ))}
      </div>
    </div>
  );
}
