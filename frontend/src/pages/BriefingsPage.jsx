import React, { useState } from 'react';
import { mockBriefings, mockBriefingDetail } from '../api/mockData';
import { formatDate } from '../utils/formatters';
import './BriefingsPage.css';

export default function BriefingsPage() {
  const [selectedId, setSelectedId] = useState(null);
  
  const selectedBriefing = selectedId === mockBriefingDetail.briefing_id ? mockBriefingDetail : null;

  return (
    <div className="briefings-page fade-in">
      <div className="briefings-sidebar">
        <h2 className="sidebar-title">Briefing Archive</h2>
        <div className="briefing-cards">
          {mockBriefings.map(b => (
            <div 
              key={b.briefing_id} 
              id={`briefing-${b.briefing_id}`}
              className={`briefing-card card card--clickable ${selectedId === b.briefing_id ? 'active' : ''}`}
              onClick={() => setSelectedId(b.briefing_id)}
            >
              <div className="briefing-card-header">
                <h4>{formatDate(b.period_start)} – {formatDate(b.period_end)}</h4>
                <span className={`status-badge status-${b.delivery_status}`}>{b.delivery_status}</span>
              </div>
              <div className="briefing-meta">Generated: {formatDate(b.generated_at)}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="briefing-viewer">
        {!selectedBriefing ? (
          <div className="empty-state">
            <p>Select a briefing to view</p>
          </div>
        ) : (
          <div className="viewer-content card">
            <div className="viewer-header">
              <div className="viewer-meta">
                <span>Period: {formatDate(selectedBriefing.period_start)} – {formatDate(selectedBriefing.period_end)}</span>
                <span>Generated: {formatDate(selectedBriefing.generated_at)}</span>
                <span className={`status-badge status-${selectedBriefing.delivery_status}`}>{selectedBriefing.delivery_status}</span>
              </div>
            </div>
            {/* Simple markdown render for the mock */}
            <div 
              className="markdown-body" 
              dangerouslySetInnerHTML={{ __html: parseMarkdown(selectedBriefing.body_md) }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

// Basic markdown parser for mock purposes
function parseMarkdown(md) {
  let html = md
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^## (.*$)/gim, '<h2>$1</h2>')
    .replace(/^# (.*$)/gim, '<h1>$1</h1>')
    .replace(/\*\*(.*)\*\*/gim, '<strong>$1</strong>')
    .replace(/\*(.*)\*/gim, '<em>$1</em>')
    .replace(/\[(.*?)\]/gim, '<a href="#" class="citation-link">[$1]</a>')
    .replace(/^\- (.*$)/gim, '<li>$1</li>');
  
  html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
  
  return html.split('\n').map(line => {
    if (!line.match(/<(h|ul|li|strong|em|a)/) && line.trim().length > 0) {
      return `<p>${line}</p>`;
    }
    return line;
  }).join('\n');
}
