import React from 'react';
import { Info } from 'lucide-react';
import { ScoreBar } from '../common/ScoreBar';
import './ScoreExplainer.css';

const TOOLTIPS = {
  impact: 'How damaging the vulnerability is, based on its CVSS score.',
  likelihood: 'How likely it is to be exploited, per EPSS — or 100% if confirmed actively exploited.',
  adoption: 'How many distinct threat actors or malware families are known to use it.',
  novelty: 'How recently something significant happened with this CVE.',
  credibility: 'How trustworthy the sources reporting on it are.',
  centrality: 'How connected this CVE is to other threat activity in the graph.',
};

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
          <Info size={14} className="info-icon" title="How bad this CVE is, independent of whether it's relevant to you right now" />
        </h4>
        <div className="bars-container">
          <ScoreBar label="Impact (40%)" value={(fallbackScores.impact * 100).toFixed(0) + '%'} score={fallbackScores.impact} tooltip={TOOLTIPS.impact} />
          <ScoreBar label="Likelihood (40%)" value={(fallbackScores.likelihood * 100).toFixed(0) + '%'} score={fallbackScores.likelihood} tooltip={TOOLTIPS.likelihood} />
          <ScoreBar label="Adoption (20%)" value={(fallbackScores.adoption * 100).toFixed(0) + '%'} score={fallbackScores.adoption} tooltip={TOOLTIPS.adoption} />
        </div>
      </div>

      <div className="score-section">
        <h4 className="section-title">
          Relevance Factors
          <Info size={14} className="info-icon" title="Whether this CVE deserves attention right now, separate from raw severity" />
        </h4>
        <div className="bars-container">
          <ScoreBar label="Novelty (30%)" value={(fallbackScores.novelty * 100).toFixed(0) + '%'} score={fallbackScores.novelty} tooltip={TOOLTIPS.novelty} />
          <ScoreBar label="Credibility (40%)" value={(fallbackScores.credibility * 100).toFixed(0) + '%'} score={fallbackScores.credibility} tooltip={TOOLTIPS.credibility} />
          <ScoreBar label="Centrality (30%)" value={(fallbackScores.centrality * 100).toFixed(0) + '%'} score={fallbackScores.centrality} tooltip={TOOLTIPS.centrality} />
        </div>
      </div>
    </div>
  );
}
