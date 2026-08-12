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

  // Transparent version for cell background tinting
  const getHeatBg = (heat) => {
    if (heat > 0.8) return 'var(--color-critical-bg)';
    if (heat > 0.6) return 'var(--color-high-bg)';
    if (heat > 0.4) return 'var(--color-medium-bg)';
    return 'var(--color-primary-bg)';
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
          <Link
            key={ttp.id}
            to="/heatmap"
            className="mini-heatmap__cell"
            style={{ 
              backgroundColor: getHeatBg(ttp.heat),
              borderLeft: `3px solid ${getHeatColor(ttp.heat)}`,
            }}
            id={`mini-heatmap-cell-${ttp.id}`}
          >
            <div className="mini-heatmap__cell-top">
              <span className="mini-heatmap__cell-id">{ttp.id}</span>
              <span
                className="mini-heatmap__cell-heat"
                style={{ color: getHeatColor(ttp.heat) }}
              >
                {ttp.heat.toFixed(2)}
              </span>
            </div>
            <div className="mini-heatmap__cell-name">{ttp.name}</div>
            <div className="mini-heatmap__cell-meta">
              {ttp.exploiter_count} exploiter{ttp.exploiter_count !== 1 ? 's' : ''}
            </div>

            {/* Hover tooltip with more detail */}
            <div className="mini-heatmap__tooltip">
              <div className="mini-heatmap__tooltip-title">{ttp.name}</div>
              <div className="mini-heatmap__tooltip-row">
                <span>Heat Score</span>
                <span style={{ color: getHeatColor(ttp.heat), fontWeight: 600 }}>
                  {ttp.heat.toFixed(2)}
                </span>
              </div>
              <div className="mini-heatmap__tooltip-row">
                <span>Exploiters</span>
                <span>{ttp.exploiter_count}</span>
              </div>
              {ttp.top_exploiters && ttp.top_exploiters.length > 0 && (
                <div className="mini-heatmap__tooltip-actors">
                  {ttp.top_exploiters.slice(0, 3).join(', ')}
                </div>
              )}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
