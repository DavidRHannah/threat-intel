import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';
import './KpiCard.css';
import { formatNumber } from '../../utils/formatters';

export function KpiCard({ title, value, delta, icon: Icon, accentColor }) {
  const isLoading = value === undefined;
  
  return (
    <div 
      className="kpi-card card card--clickable"
      style={{ '--card-accent': accentColor }}
    >
      <div className="kpi-card__header">
        <h3 className="kpi-card__title">{title}</h3>
        {Icon && (
          <div className="kpi-card__icon-wrapper" style={{ backgroundColor: `${accentColor}20`, color: accentColor }}>
            <Icon size={20} />
          </div>
        )}
      </div>
      
      <div className="kpi-card__body">
        {isLoading ? (
          <div className="kpi-card__skeleton skeleton"></div>
        ) : (
          <div className="kpi-card__value">{formatNumber(value)}</div>
        )}
      </div>
      
      {!isLoading && delta !== undefined && (
        <div className="kpi-card__footer">
          <div className={`kpi-card__delta ${delta >= 0 ? 'kpi-card__delta--positive' : 'kpi-card__delta--negative'}`}>
            {delta >= 0 ? <TrendingUp size={16} /> : <TrendingDown size={16} />}
            <span>{Math.abs(delta)}</span>
          </div>
          <span className="kpi-card__delta-text">vs last period</span>
        </div>
      )}
    </div>
  );
}
