import React, { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';
import { useTopCves } from '../api/hooks';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { formatScore, formatDate } from '../utils/formatters';
import './ThreatsPage.css';

export default function ThreatsPage() {
  const [sortField, setSortField] = useState('severity_score');
  const [sortDirection, setSortDirection] = useState('desc');
  const [showKevOnly, setShowKevOnly] = useState(false);
  const { data, isLoading } = useTopCves(100);
  const cves = data?.cves ?? [];

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const SortIcon = ({ field }) => {
    if (sortField !== field) return <ArrowUpDown size={14} className="sort-icon-idle" />;
    return sortDirection === 'asc' ? <ArrowUp size={14} className="sort-icon-active" /> : <ArrowDown size={14} className="sort-icon-active" />;
  };

  const filteredAndSortedData = useMemo(() => {
    let data = [...cves];
    
    if (showKevOnly) {
      data = data.filter(cve => cve.exploited_in_wild);
    }

    data.sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (typeof valA === 'string') {
        valA = valA.toLowerCase();
        valB = valB.toLowerCase();
      }
      if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
      if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return data;
  }, [cves, sortField, sortDirection, showKevOnly]);

  return (
    <div className="page-container threats-page fade-in">
      <div className="page-header">
        <h1 className="page-title">Top Threats</h1>
        <p className="page-description">Triage and investigate highest-priority vulnerabilities.</p>
      </div>

      <div className="threats-controls card">
        <div className="control-group row-group">
          <input 
            type="checkbox" 
            id="kev-toggle"
            checked={showKevOnly}
            onChange={(e) => setShowKevOnly(e.target.checked)}
          />
          <label htmlFor="kev-toggle" className="control-label">CISA KEV Listed Only</label>
        </div>
      </div>

      <div className="card table-container">
        {isLoading && <p className="empty-state">Loading…</p>}
        {!isLoading && (
          <table className="threats-table">
            <thead>
              <tr>
                <th onClick={() => handleSort('cve_id')} className="sortable-th">CVE ID <SortIcon field="cve_id" /></th>
                <th>Description</th>
                <th onClick={() => handleSort('severity_score')} className="sortable-th">Severity <SortIcon field="severity_score" /></th>
                <th onClick={() => handleSort('cvss_score')} className="sortable-th">CVSS <SortIcon field="cvss_score" /></th>
                <th onClick={() => handleSort('epss_score')} className="sortable-th">EPSS <SortIcon field="epss_score" /></th>
                <th onClick={() => handleSort('relevance_score')} className="sortable-th">Relevance <SortIcon field="relevance_score" /></th>
                <th onClick={() => handleSort('exploited_in_wild')} className="sortable-th">KEV <SortIcon field="exploited_in_wild" /></th>
                <th onClick={() => handleSort('published_date')} className="sortable-th">Published <SortIcon field="published_date" /></th>
              </tr>
            </thead>
            <tbody>
              {filteredAndSortedData.map(cve => (
                <tr key={cve.id} className="threat-row">
                  <td className="cve-id-cell">
                    <Link to={`/entity/cve/${cve.id}`}>{cve.cve_id}</Link>
                  </td>
                  <td className="desc-cell"><div className="truncate-text">{cve.description}</div></td>
                  <td><SeverityBadge score={cve.severity_score} /></td>
                  <td>{formatScore(cve.cvss_score, 1)}</td>
                  <td>{(cve.epss_score * 100).toFixed(0)}%</td>
                  <td>{(cve.relevance_score * 100).toFixed(0)}%</td>
                  <td>
                    {cve.exploited_in_wild ? <span className="badge badge--critical">Yes</span> : <span className="badge badge--low">No</span>}
                  </td>
                  <td className="date-cell">{formatDate(cve.published_date)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
