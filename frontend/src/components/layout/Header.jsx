import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Bell } from 'lucide-react';
import { useSearch } from '../../api/hooks';
import { EntityBadge } from '../common/EntityBadge';
import './Header.css';

const DROPDOWN_RESULT_LIMIT = 5;

export function Header({ title, collapsed }) {
  const navigate = useNavigate();
  const containerRef = useRef(null);
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query), 300);
    return () => clearTimeout(timer);
  }, [query]);

  const { data, isFetching } = useSearch(debouncedQuery);
  const results = (data?.results ?? []).slice(0, DROPDOWN_RESULT_LIMIT);
  // Covers both the debounce wait (query hasn't settled into debouncedQuery yet) and the
  // actual network fetch that follows -- checking isFetching alone misses the debounce gap,
  // checking the gap alone misses the fetch itself, which is what let "No results found"
  // flash before real results arrived.
  const isSearching = query.trim() !== debouncedQuery.trim() || isFetching;

  useEffect(() => {
    function handleClickOutside(event) {
      if (containerRef.current && !containerRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  function goToResult(result) {
    navigate(`/entity/${result._type}/${result.id}`);
    setQuery('');
    setDebouncedQuery('');
    setIsOpen(false);
  }

  function goToSearchPage() {
    if (!query.trim()) return;
    navigate(`/search?q=${encodeURIComponent(query.trim())}`);
    setIsOpen(false);
  }

  function handleKeyDown(event) {
    if (event.key === 'Enter') {
      goToSearchPage();
    } else if (event.key === 'Escape') {
      setIsOpen(false);
    }
  }

  const showDropdown = isOpen && query.trim().length > 0;

  return (
    <header className="app-header">
      <div className="app-header-left">
        <h1 className="app-header-title">{title}</h1>
      </div>

      <div className="app-header-center">
        <div className="app-search-container" ref={containerRef}>
          <Search
            className="app-search-icon"
            size={18}
            onClick={goToSearchPage}
            style={{ pointerEvents: query.trim() ? 'auto' : 'none', cursor: 'pointer' }}
          />
          <input
            type="text"
            id="global-search-input"
            className="app-search-input"
            placeholder="Search threats, CVEs, actors, campaigns..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setIsOpen(true);
            }}
            onFocus={() => setIsOpen(true)}
            onKeyDown={handleKeyDown}
          />

          {showDropdown && (
            <div className="app-search-dropdown card">
              {isSearching ? (
                <div className="app-search-dropdown__status">
                  <span className="app-search-dropdown__spinner" />
                  Searching…
                </div>
              ) : results.length === 0 ? (
                <div className="app-search-dropdown__status">No results found</div>
              ) : (
                <>
                  {results.map((result) => (
                    <button
                      type="button"
                      key={`${result._type}-${result.id}`}
                      className="app-search-dropdown__item"
                      onClick={() => goToResult(result)}
                    >
                      <EntityBadge type={result._type} />
                      <span className="app-search-dropdown__item-name">
                        {result.cve_id || result.name}
                      </span>
                    </button>
                  ))}
                  <button
                    type="button"
                    className="app-search-dropdown__item app-search-dropdown__see-all"
                    onClick={goToSearchPage}
                  >
                    See all results for &ldquo;{query.trim()}&rdquo;
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="app-header-right">
        <button id="notification-btn" className="btn btn--ghost header-btn" title="Notifications">
          <Bell size={20} />
          <span className="notification-badge">3</span>
        </button>
        <button id="user-profile-btn" className="user-avatar-btn" title="User Profile">
          <div className="user-avatar">
            DH
          </div>
        </button>
      </div>
    </header>
  );
}
