import { getSeverityBand, SEVERITY_BANDS, formatScore } from '../../utils/formatters';

export function SeverityBadge({ band, score, showScore = false }) {
  let severityInfo;
  
  if (band && SEVERITY_BANDS[band.toLowerCase()]) {
    severityInfo = SEVERITY_BANDS[band.toLowerCase()];
  } else {
    severityInfo = getSeverityBand(score);
  }

  return (
    <span className={`badge ${severityInfo.className}`}>
      {severityInfo.label}
      {showScore && score != null && ` (${formatScore(score)})`}
    </span>
  );
}
