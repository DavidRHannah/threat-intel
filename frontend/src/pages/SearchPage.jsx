import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Search } from 'lucide-react';
import { useSearch } from '../api/hooks';
import { EntityBadge } from '../components/common/EntityBadge';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { formatScore } from '../utils/formatters';
import './SearchPage.css';

export default function SearchPage() {
  const [searchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') || '';
  const [query, setQuery] = useState(initialQuery);
  const [debouncedQuery, setDebouncedQuery] = useState(initialQuery);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query);
    }, 300);
    return () => clearTimeout(timer);
  }, [query]);

  // Re-searching from the header while already on this page changes the URL's `q` without
  // remounting SearchPage (same route), so sync local state to it explicitly.
  useEffect(() => {
    const q = searchParams.get('q') || '';
    if (q && q !== query) {
      setQuery(q);
      setDebouncedQuery(q);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const { data } = useSearch(debouncedQuery);
  const results = data?.results ?? [];

  return (
    <div className="search-page fade-in">
      <div className="search-header">
        <div className="search-input-wrapper">
          <Search className="search-icon" size={24} />
          <input
            id="search-input-main"
            type="text"
            placeholder="Search across CVEs, threat actors, malware families, TTPs, and IOCs..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="search-input"
          />
        </div>
      </div>
      
      <div className="search-layout">
        <aside className="search-sidebar">
          <h3>Filters</h3>
          <div className="filter-group">
            <h4>Entity Type</h4>
            <label><input type="checkbox" id="filter-cve" /> CVE</label>
            <label><input type="checkbox" id="filter-actor" /> Actor</label>
            <label><input type="checkbox" id="filter-malware" /> Malware</label>
            <label><input type="checkbox" id="filter-ttp" /> TTP</label>
            <label><input type="checkbox" id="filter-ioc" /> IOC</label>
          </div>
          <div className="filter-group">
            <h4>Severity Range</h4>
            <input type="range" id="filter-severity" min="0" max="1" step="0.1" />
          </div>
          <div className="filter-group">
            <h4>Relevance</h4>
            <input type="range" id="filter-relevance" min="0" max="1" step="0.1" />
          </div>
        </aside>

        <main className="search-results">
          {!debouncedQuery ? (
            <div className="empty-state">
              <p>Search across CVEs, threat actors, malware families, TTPs, and IOCs</p>
            </div>
          ) : results.length === 0 ? (
            <div className="empty-state">
              <p>No results found</p>
            </div>
          ) : (
            <div className="results-list">
              {results.map((result) => (
                <Link to={`/entity/${result._type}/${result.id}`} key={`${result._type}-${result.id}`} className="result-card card card--clickable">
                  <div className="result-header">
                    <EntityBadge type={result._type} />
                    <span className="result-id">{result.cve_id || result.name}</span>
                    {result._type === 'cve' && <SeverityBadge score={result.severity_score} />}
                  </div>
                  <p className="result-desc">{result.description || `Relevance: ${formatScore(result.relevance_score)}`}</p>
                </Link>
              ))}
            </div>
          )}
        </main>
      </div>

      <div className="qa-section">
        <div className="qa-panel">
          <p>Ask a question (coming soon)</p>
          <input type="text" id="qa-input" disabled placeholder="Ask about the results..." />
        </div>
      </div>
    </div>
  );
}
