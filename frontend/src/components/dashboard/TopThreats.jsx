import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import './TopThreats.css';
import { useTopCves, useTopActors, useTopMalware } from '../../api/hooks';
import { formatScore } from '../../utils/formatters';

const SeverityBadge = ({ severity }) => {
  const normalized = severity?.toLowerCase() || 'unknown';
  return <span className={`badge badge--${normalized}`}>{normalized}</span>;
};

export function TopThreats() {
  const [activeTab, setActiveTab] = useState('cves');
  const { data: cvesData } = useTopCves(5);
  const { data: actorsData } = useTopActors(5);
  const { data: malwareData } = useTopMalware(5);
  const topCves = cvesData?.cves ?? [];
  const topActors = actorsData?.actors ?? [];
  const topMalware = malwareData?.malware ?? [];

  return (
    <div className="top-threats card fade-in" id="top-threats">
      <div className="top-threats__header">
        <h2 className="top-threats__title">Top Threats</h2>
        <div className="top-threats__tabs" role="tablist">
          <button
            role="tab"
            aria-selected={activeTab === 'cves'}
            className={`top-threats__tab ${activeTab === 'cves' ? 'active' : ''}`}
            onClick={() => setActiveTab('cves')}
            id="tab-cves"
          >
            CVEs
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'actors'}
            className={`top-threats__tab ${activeTab === 'actors' ? 'active' : ''}`}
            onClick={() => setActiveTab('actors')}
            id="tab-actors"
          >
            Actors
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'malware'}
            className={`top-threats__tab ${activeTab === 'malware' ? 'active' : ''}`}
            onClick={() => setActiveTab('malware')}
            id="tab-malware"
          >
            Malware
          </button>
        </div>
      </div>

      <div className="top-threats__content">
        {activeTab === 'cves' && (
          <div className="top-threats__list" role="tabpanel" id="panel-cves">
            {topCves.slice(0, 5).map((cve) => (
              <Link key={cve.id} to={`/entity/cve/${cve.id}`} className="threat-item">
                <div className="threat-item__main">
                  <span className="threat-item__name">{cve.cve_id}</span>
                  <SeverityBadge severity={cve.severity_band} />
                  {cve.exploited_in_wild && <span className="badge badge--critical">KEV</span>}
                </div>
                <div className="threat-item__stats">
                  <span className="threat-item__stat" title="CVSS Score">CVSS: {formatScore(cve.cvss_score, 1)}</span>
                  <span className="threat-item__stat" title="EPSS Score">EPSS: {formatScore(cve.epss_score, 2)}</span>
                </div>
              </Link>
            ))}
          </div>
        )}

        {activeTab === 'actors' && (
          <div className="top-threats__list" role="tabpanel" id="panel-actors">
            {topActors.slice(0, 5).map((actor) => (
              <Link key={actor.id} to={`/entity/actor/${actor.id}`} className="threat-item">
                <div className="threat-item__main">
                  <span className="threat-item__name">{actor.name}</span>
                  <span className="threat-item__flag" title={actor.origin_country}>
                    {actor.origin_country === 'Russia' ? '🇷🇺' :
                     actor.origin_country === 'North Korea' ? '🇰🇵' :
                     actor.origin_country === 'China' ? '🇨🇳' : '🏳️'}
                  </span>
                  <span className="badge badge--unknown">{actor.motivation}</span>
                </div>
              </Link>
            ))}
          </div>
        )}

        {activeTab === 'malware' && (
          <div className="top-threats__list" role="tabpanel" id="panel-malware">
            {topMalware.slice(0, 5).map((malware) => (
              <Link key={malware.id} to={`/entity/malware/${malware.id}`} className="threat-item">
                <div className="threat-item__main">
                  <span className="threat-item__name">{malware.name}</span>
                  <span className="badge badge--unknown">{malware.malware_type}</span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
