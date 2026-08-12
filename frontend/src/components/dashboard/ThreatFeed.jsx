import React from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw, Newspaper } from 'lucide-react';
import './ThreatFeed.css';
import { mockRecentStories } from '../../api/mockData';
import { formatRelativeTime } from '../../utils/formatters';

/**
 * Derives a detail-page link from a story's primary entity.
 * Falls back to search with the headline as query when no entity is present.
 */
function storyLink(story) {
  const primary = story.entities?.[0];
  if (!primary) return `/search?q=${encodeURIComponent(story.headline)}`;

  const id = primary.id || primary.name;
  return `/entity/${primary.type}/${encodeURIComponent(id)}`;
}

export function ThreatFeed() {
  return (
    <div className="threat-feed card fade-in" id="threat-feed">
      <div className="threat-feed__header">
        <h2 className="threat-feed__title">Live Threat Feed</h2>
        <button className="btn btn--ghost btn--sm" aria-label="Refresh feed" id="refresh-feed-btn">
          <RefreshCw size={16} />
        </button>
      </div>
      
      <div className="threat-feed__list">
        {mockRecentStories.map((story) => (
          <div key={story.id} className="threat-feed__item" id={`story-${story.id}`}>
            <div className="threat-feed__item-content">
              <Link to={storyLink(story)} className="threat-feed__headline">
                {story.headline}
              </Link>
              
              <div className="threat-feed__meta">
                <div className="threat-feed__articles">
                  <Newspaper size={14} />
                  <span>{story.article_count} articles</span>
                </div>
                
                <div className="threat-feed__entities">
                  {story.entities.map((entity, idx) => (
                    <span 
                      key={idx} 
                      className={`badge badge--${entity.type}`}
                    >
                      {entity.name || entity.id}
                    </span>
                  ))}
                </div>
                
                <div className="threat-feed__time">
                  {formatRelativeTime(story.created_at)}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

