import React from 'react';
import { Info } from 'lucide-react';
import { ScoreBar } from '../common/ScoreBar';
import './ScoreExplainer.css';

export function ScoreExplainer({ scores }) {
  // Using fallback scores if none provided
  const fallbackScores = scores || {
    impact: 0.85, likelihood: 0.92, adoption: 0.45,
    novelty: 0.76, credibility: 0.88, centrality: 0.91
  };

  return (
    <div className="score-explainer card">
      <h3 className="panel-title">Score Breakdown</h3>
      
      <div className="score-section">
        <h4 className="section-title">
          Severity Factors
          <Info size={14} className="info-icon" title="Factors contributing to the overall severity score" />
        </h4>
        <div className="bars-container">
          <ScoreBar label="Impact (40%)" value={(fallbackScores.impact * 100).toFixed(0) + '%'} score={fallbackScores.impact} />
          <ScoreBar label="Likelihood (40%)" value={(fallbackScores.likelihood * 100).toFixed(0) + '%'} score={fallbackScores.likelihood} />
          <ScoreBar label="Adoption (20%)" value={(fallbackScores.adoption * 100).toFixed(0) + '%'} score={fallbackScores.adoption} />
        </div>
      </div>

      <div className="score-section">
        <h4 className="section-title">
          Relevance Factors
          <Info size={14} className="info-icon" title="Factors indicating relevance to your environment" />
        </h4>
        <div className="bars-container">
          <ScoreBar label="Novelty (30%)" value={(fallbackScores.novelty * 100).toFixed(0) + '%'} score={fallbackScores.novelty} />
          <ScoreBar label="Credibility (40%)" value={(fallbackScores.credibility * 100).toFixed(0) + '%'} score={fallbackScores.credibility} />
          <ScoreBar label="Centrality (30%)" value={(fallbackScores.centrality * 100).toFixed(0) + '%'} score={fallbackScores.centrality} />
        </div>
      </div>
    </div>
  );
}
