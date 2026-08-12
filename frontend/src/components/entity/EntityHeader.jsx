import React from 'react';
import { EntityBadge } from '../common/EntityBadge';
import { SeverityBadge } from '../common/SeverityBadge';
import { ScoreBar } from '../common/ScoreBar';
import { getEntityType } from '../../utils/formatters';
import './EntityHeader.css';

export function EntityHeader({ entity }) {
  if (!entity) return null;

  const entityType = getEntityType(entity.type);

  return (
    <div className="entity-header card" style={{ borderTop: `4px solid ${entityType.color}` }}>
      <div className="entity-header-top">
        <EntityBadge type={entity.type} />
        {entity.exploited_in_wild && (
          <span className="badge badge--critical">KEV Listed</span>
        )}
        {entity.type === 'cve' && entity.severity_score !== undefined && (
          <SeverityBadge score={entity.severity_score} />
        )}
        {(entity.type === 'actor' || entity.type === 'threat_actor') && entity.motivation && (
          <span className="badge badge--unknown">{entity.motivation}</span>
        )}
      </div>

      <div className="entity-title-section">
        <h1 className="entity-title">{entity.cve_id || entity.name || entity.id}</h1>
        {(entity.type === 'actor' || entity.type === 'threat_actor') && entity.origin_country && (
          <div className="entity-aliases">
            Country: {entity.origin_country}
            {entity.aliases && ` | Aliases: ${entity.aliases.join(', ')}`}
          </div>
        )}
        <p className="entity-description">{entity.description}</p>
      </div>

      <div className="entity-scores-row">
        {entity.cvss_score !== undefined && (
          <ScoreBar label="CVSS Score" score={entity.cvss_score / 10} value={entity.cvss_score.toFixed(1)} />
        )}
        {entity.epss_score !== undefined && (
          <ScoreBar label="EPSS Score" score={entity.epss_score} value={(entity.epss_score * 100).toFixed(1) + '%'} />
        )}
        {entity.relevance_score !== undefined && (
          <ScoreBar label="Relevance" score={entity.relevance_score} value={(entity.relevance_score * 100).toFixed(1) + '%'} />
        )}
      </div>
    </div>
  );
}
