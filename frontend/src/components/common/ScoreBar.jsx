import './ScoreBar.css';
import { formatScore, getSeverityBand } from '../../utils/formatters';

export function ScoreBar({ value, label, color }) {
  const clampedValue = Math.max(0, Math.min(1, value || 0));
  const percent = `${(clampedValue * 100).toFixed(1)}%`;
  
  const barColor = color || getSeverityBand(clampedValue).color;

  return (
    <div className="score-bar-container">
      {label && (
        <div className="score-bar-header">
          <span className="score-bar-label">{label}</span>
          <span className="score-bar-value">{formatScore(clampedValue)}</span>
        </div>
      )}
      <div className="score-bar-track">
        <div 
          className="score-bar-fill" 
          style={{ 
            width: percent,
            backgroundColor: barColor
          }}
        />
      </div>
      {!label && (
        <span className="score-bar-value-inline">{formatScore(clampedValue)}</span>
      )}
    </div>
  );
}
