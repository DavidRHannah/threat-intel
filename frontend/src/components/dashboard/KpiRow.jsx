import React from 'react';
import { ShieldAlert, Flame, Users, Newspaper } from 'lucide-react';
import { KpiCard } from './KpiCard';
import './KpiRow.css';
import { useStats } from '../../api/hooks';

export function KpiRow() {
  const { data: stats } = useStats();

  return (
    <div className="kpi-row fade-in">
      <KpiCard
        title="Critical CVEs"
        value={stats?.critical_cves}
        delta={stats?.trend_deltas?.critical_cves}
        icon={ShieldAlert}
        accentColor="var(--color-critical)"
      />
      <KpiCard
        title="Active Exploits"
        value={stats?.active_exploits}
        delta={stats?.trend_deltas?.active_exploits}
        icon={Flame}
        accentColor="var(--color-high)"
      />
      <KpiCard
        title="Threat Actors"
        value={stats?.total_actors}
        delta={stats?.trend_deltas?.total_actors}
        icon={Users}
        accentColor="var(--color-entity-actor)"
      />
      <KpiCard
        title="Articles Today"
        value={stats?.articles_today}
        delta={stats?.trend_deltas?.articles_today}
        icon={Newspaper}
        accentColor="var(--color-primary)"
      />
    </div>
  );
}
