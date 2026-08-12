import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { mockSubgraph } from '../api/mockData';
import { EntityHeader } from '../components/entity/EntityHeader';
import { ScoreExplainer } from '../components/entity/ScoreExplainer';
import { EvidenceTabs } from '../components/entity/EvidenceTabs';
import { EgoGraph } from '../components/graph/EgoGraph';
import { ChevronRight } from 'lucide-react';
import './EntityDetailPage.css';

export default function EntityDetailPage() {
  const { type, id } = useParams();
  
  const { node, neighbors, edges } = mockSubgraph;

  return (
    <div className="page-container entity-page fade-in">
      <div className="breadcrumb">
        <Link to="/">Dashboard</Link>
        <ChevronRight size={14} className="breadcrumb-icon" />
        <span className="current">{node.cve_id || node.name || id}</span>
      </div>

      <EntityHeader entity={node} />

      <div className="entity-middle-row">
        <div className="entity-col">
          <ScoreExplainer scores={{
            impact: 0.9, likelihood: 0.95, adoption: 0.5,
            novelty: 0.8, credibility: 0.9, centrality: 0.85
          }} />
        </div>
        <div className="entity-col">
          <EgoGraph 
            data={mockSubgraph} 
            onNodeClick={(n) => console.log('Node clicked', n)} 
          />
        </div>
      </div>

      <EvidenceTabs subgraph={mockSubgraph} />
    </div>
  );
}
