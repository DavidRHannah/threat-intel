import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { useSubgraph } from '../api/hooks';
import { EntityHeader } from '../components/entity/EntityHeader';
import { ScoreExplainer } from '../components/entity/ScoreExplainer';
import { EvidenceTabs } from '../components/entity/EvidenceTabs';
import { EgoGraph } from '../components/graph/EgoGraph';
import { ChevronRight } from 'lucide-react';
import './EntityDetailPage.css';

export default function EntityDetailPage() {
  const { id } = useParams();
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

  return (
    <div className="page-container entity-page fade-in">
      <div className="breadcrumb">
        <Link to="/">Dashboard</Link>
        <ChevronRight size={14} className="breadcrumb-icon" />
        <span className="current">{entity.cve_id || entity.name || id}</span>
      </div>

      <EntityHeader entity={entity} />

      <div className="entity-middle-row">
        <div className="entity-col">
          <ScoreExplainer scores={{
            impact: 0.9, likelihood: 0.95, adoption: 0.5,
            novelty: 0.8, credibility: 0.9, centrality: 0.85
          }} />
        </div>
        <div className="entity-col">
          <EgoGraph
            data={subgraph}
            onNodeClick={(n) => console.log('Node clicked', n)}
          />
        </div>
      </div>

      <EvidenceTabs subgraph={subgraph} />
    </div>
  );
}
