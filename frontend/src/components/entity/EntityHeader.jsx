import React from 'react';
import ReactMarkdown from 'react-markdown';
import { EntityBadge } from '../common/EntityBadge';
import { SeverityBadge } from '../common/SeverityBadge';
import { ScoreBar } from '../common/ScoreBar';
import { getEntityType, stripCitations } from '../../utils/formatters';
import './EntityHeader.css';

// Neo4j returns absent numeric properties as null, not undefined, so a `!== undefined`
// guard lets null through and `null.toFixed()` throws. 1641 of 1677 live CVE nodes have
// no cvss_score, so this is the common case, not the edge case.
const isNumber = (v) => typeof v === 'number' && Number.isFinite(v);

const descriptionLinkRenderer = ({ href, children }) => (
  <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
);

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
        {entity.description && (
          <div className="entity-description">
            <ReactMarkdown components={{ a: descriptionLinkRenderer }}>
              {stripCitations(entity.description)}
            </ReactMarkdown>
          </div>
        )}
      </div>

      <div className="entity-scores-row">
        {isNumber(entity.cvss_score) && (
          <ScoreBar label="CVSS Score" score={entity.cvss_score / 10} value={entity.cvss_score.toFixed(1)} />
        )}
        {isNumber(entity.epss_score) && (
          <ScoreBar label="EPSS Score" score={entity.epss_score} value={(entity.epss_score * 100).toFixed(1) + '%'} />
        )}
      </div>
    </div>
  );
}
