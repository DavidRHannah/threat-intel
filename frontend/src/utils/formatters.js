/* Score formatting utilities */

export const SEVERITY_BANDS = {
  critical: { label: 'Critical', min: 0.8, color: 'var(--color-critical)', className: 'badge--critical' },
  high: { label: 'High', min: 0.6, color: 'var(--color-high)', className: 'badge--high' },
  medium: { label: 'Medium', min: 0.4, color: 'var(--color-medium)', className: 'badge--medium' },
  low: { label: 'Low', min: 0, color: 'var(--color-low)', className: 'badge--low' },
  unknown: { label: 'Unknown', min: -1, color: 'var(--color-unknown)', className: 'badge--unknown' },
};

export function getSeverityBand(score) {
  if (score == null) return SEVERITY_BANDS.unknown;
  if (score >= 0.8) return SEVERITY_BANDS.critical;
  if (score >= 0.6) return SEVERITY_BANDS.high;
  if (score >= 0.4) return SEVERITY_BANDS.medium;
  return SEVERITY_BANDS.low;
}

export function formatScore(score, decimals = 2) {
  if (score == null) return '—';
  return Number(score).toFixed(decimals);
}

export function formatPercent(score) {
  if (score == null) return '—';
  return `${(score * 100).toFixed(1)}%`;
}

/* Entity type utilities */

export const ENTITY_TYPES = {
  cve: { label: 'CVE', color: 'var(--color-entity-cve)', className: 'badge--cve' },
  actor: { label: 'Actor', color: 'var(--color-entity-actor)', className: 'badge--actor' },
  threat_actor: { label: 'Actor', color: 'var(--color-entity-actor)', className: 'badge--actor' },
  malware: { label: 'Malware', color: 'var(--color-entity-malware)', className: 'badge--malware' },
  malware_family: { label: 'Malware', color: 'var(--color-entity-malware)', className: 'badge--malware' },
  ttp: { label: 'TTP', color: 'var(--color-entity-ttp)', className: 'badge--ttp' },
  ioc: { label: 'IOC', color: 'var(--color-entity-ioc)', className: 'badge--ioc' },
  campaign: { label: 'Campaign', color: 'var(--color-entity-campaign)', className: 'badge--campaign' },
};

export function getEntityType(type) {
  return ENTITY_TYPES[type?.toLowerCase()] || { label: type, color: 'var(--color-unknown)', className: 'badge--unknown' };
}

/* Date formatting */

export function formatDate(dateStr) {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function formatRelativeTime(dateStr) {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(dateStr);
}

export function formatNumber(num) {
  if (num == null) return '—';
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return num.toLocaleString();
}

/* Description text cleanup */

// MITRE ATT&CK descriptions embed "(Citation: <key>)" markers that reference an
// external_references list we don't ingest, so the key is meaningless on its own —
// stripped rather than shown as a broken-looking footnote.
export function stripCitations(text) {
  if (!text) return text;
  return text.replace(/\s?\(Citation:[^)]*\)/g, '').trim();
}

/* TTP tactics */

// TTP.tactic is a LIST of STIX kill-chain phase-name slugs (a technique can belong to more
// than one) -- rendering the array directly with `{n.tactic}` mashes the slugs together with
// no separator, since React joins array children with nothing between them.
export function formatTactics(tactics) {
  if (!tactics || tactics.length === 0) return '—';
  return tactics.map(t => t.split('-').map(w => w[0].toUpperCase() + w.slice(1)).join(' ')).join(', ');
}

// Sort key for grouping TTPs by tactic: a multi-tactic TTP sorts under its
// alphabetically-first tactic, so it lands in a single, consistent group rather than
// scattering across every tactic it belongs to.
export function primaryTactic(tactics) {
  if (!tactics || tactics.length === 0) return '';
  return [...tactics].sort()[0];
}
