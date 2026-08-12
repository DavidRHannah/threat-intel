import React from 'react';
import { ShieldAlert, Flame, Users, Newspaper } from 'lucide-react';
import { KpiCard } from './KpiCard';
import './KpiRow.css';
import { mockStats } from '../../api/mockData';

export function KpiRow() {
  return (
    <div className="kpi-row fade-in">
      <KpiCard 
        title="Critical CVEs" 
        value={mockStats.critical_cves} 
        delta={mockStats.trend_deltas.critical_cves} 
        icon={ShieldAlert} 
        accentColor="var(--color-critical)"
      />
      <KpiCard 
        title="Active Exploits" 
        value={mockStats.active_exploits} 
        delta={mockStats.trend_deltas.active_exploits} 
        icon={Flame} 
        accentColor="var(--color-high)"
      />
      <KpiCard 
        title="Threat Actors" 
        value={mockStats.total_actors} 
        delta={mockStats.trend_deltas.total_actors} 
        icon={Users} 
        accentColor="var(--color-entity-actor)"
      />
      <KpiCard 
        title="Articles Today" 
        value={mockStats.articles_today} 
        delta={mockStats.trend_deltas.articles_today} 
        icon={Newspaper} 
        accentColor="var(--color-primary)"
      />
    </div>
  );
}
