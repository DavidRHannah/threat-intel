import React from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw, Newspaper } from 'lucide-react';
import './ThreatFeed.css';
import { useRecentStories } from '../../api/hooks';
import { formatRelativeTime } from '../../utils/formatters';

function storyLink(story) {
  // story.id is the representative Article's own elementId (fetch_recent_stories in
  // src/delivery/queries.py) -- link to the article itself so a click shows every
  // connection extraction made from it, not just its first mentioned entity.
  return `/entity/article/${encodeURIComponent(story.id)}`;
}

export function ThreatFeed() {
  const { data, isLoading } = useRecentStories(20);
  const stories = data?.stories ?? [];

  return (
    <div className="threat-feed card fade-in" id="threat-feed">
      <div className="threat-feed__header">
        <h2 className="threat-feed__title">Live Threat Feed</h2>
        <button className="btn btn--ghost btn--sm" aria-label="Refresh feed" id="refresh-feed-btn">
          <RefreshCw size={16} />
        </button>
      </div>

      <div className="threat-feed__list">
        {isLoading && <p className="threat-feed__empty">Loading…</p>}
        {!isLoading && stories.length === 0 && (
          <p className="threat-feed__empty">No recent stories.</p>
        )}
        {stories.map((story) => (
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

