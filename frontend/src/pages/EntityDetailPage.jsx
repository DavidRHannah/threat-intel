import React from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useSubgraph } from '../api/hooks';
import { EntityHeader } from '../components/entity/EntityHeader';
import { EvidenceTabs } from '../components/entity/EvidenceTabs';
import { EgoGraph } from '../components/graph/EgoGraph';
import { ChevronRight } from 'lucide-react';
import './EntityDetailPage.css';

// Maps the subgraph API's entity.type (not the URL's cosmetic :type segment) to the list
// page an analyst would expect "back" to mean. TTP/IOC/Article/CWE have no dedicated list
// page, so they fall back to the dashboard.
const BREADCRUMB_BY_TYPE = {
  cve: { label: 'Threats', to: '/threats' },
  threat_actor: { label: 'Threat Actors', to: '/actors?tab=actors' },
  malware_family: { label: 'Malware Families', to: '/actors?tab=malware' },
  campaign: { label: 'Campaigns', to: '/actors?tab=campaigns' },
};

export default function EntityDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: subgraph, isLoading, isError, error } = useSubgraph(id);

  if (isLoading) {
    return <div className="page-container entity-page fade-in">Loading…</div>;
  }

  if (isError || !subgraph) {
    const notFound = error?.response?.status === 404;
    return (
      <div className="page-container entity-page fade-in">
        {notFound ? 'Entity not found.' : 'Failed to load entity. Please try again.'}
      </div>
    );
  }

  // `useSubgraph` already flattens `props` onto each entity, so `node` carries both the
  // structural fields (id/type/labels) and the entity's own properties.
  const { node } = subgraph;
  const entity = node;
  const backLink = BREADCRUMB_BY_TYPE[entity.type] || { label: 'Dashboard', to: '/' };

  return (
    <div className="page-container entity-page fade-in">
      <div className="breadcrumb">
        <Link to={backLink.to}>{backLink.label}</Link>
        <ChevronRight size={14} className="breadcrumb-icon" />
        <span className="current">{entity.cve_id || entity.name || id}</span>
      </div>

      <EntityHeader entity={entity} />

      <div className="entity-middle-row">
        <EgoGraph
          data={subgraph}
          onNodeClick={(n) => {
            if (n.id === entity.id) return;
            navigate(`/entity/${n.type}/${n.id}`);
          }}
        />
      </div>

      <EvidenceTabs subgraph={subgraph} />
    </div>
  );
}
