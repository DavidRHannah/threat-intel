import './ScoreBar.css';
import { formatScore, getSeverityBand } from '../../utils/formatters';

// `score` is the 0-1 magnitude that drives the bar; `value` is the pre-formatted
// display string. Every call site passes both -- the component previously took only
// `value` and used that display STRING as the bar width, so "24.4%" became NaN and
// "9.8" clamped to a permanently full bar.
export function ScoreBar({ score, value, label, color, tooltip }) {
  const numericScore = typeof score === 'number' && Number.isFinite(score) ? score : 0;
  const clampedValue = Math.max(0, Math.min(1, numericScore));
  const percent = `${(clampedValue * 100).toFixed(1)}%`;
  const display = value != null ? value : formatScore(clampedValue);

  const barColor = color || getSeverityBand(clampedValue).color;

  return (
    <div className="score-bar-container">
      {label && (
        <div className="score-bar-header">
          <span className="score-bar-label" title={tooltip}>{label}</span>
          <span className="score-bar-value">{display}</span>
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
        <span className="score-bar-value-inline">{display}</span>
      )}
    </div>
  );
}
