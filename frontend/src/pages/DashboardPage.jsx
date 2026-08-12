import React from 'react';
import './DashboardPage.css';
import { KpiRow } from '../components/dashboard/KpiRow';
import { ThreatFeed } from '../components/dashboard/ThreatFeed';
import { TopThreats } from '../components/dashboard/TopThreats';
import { MiniHeatmap } from '../components/dashboard/MiniHeatmap';

export default function DashboardPage() {
  return (
    <div className="dashboard-page fade-in" id="dashboard-page">
      <header className="dashboard-page__header">
        <h1 className="dashboard-page__title">Dashboard</h1>
      </header>
      
      <div className="dashboard-page__content">
        <section className="dashboard-page__kpi-section">
          <KpiRow />
        </section>
        
        <div className="dashboard-page__main-grid">
          <div className="dashboard-page__left-column">
            <MiniHeatmap />
            <TopThreats />
          </div>
          
          <div className="dashboard-page__right-column">
            <ThreatFeed />
          </div>
        </div>
      </div>
    </div>
  );
}
