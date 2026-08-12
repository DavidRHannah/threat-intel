import React, { useState } from 'react';
import { Eye, EyeOff, Copy, RefreshCw } from 'lucide-react';
import { useTheme } from '../hooks/useTheme';
import './SettingsPage.css';

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const [showApiKey, setShowApiKey] = useState(false);
  
  const apiKey = 'xr-ak-f8a7b2c4d9e1b5c8d3e2f1a4b7c6d9e8';

  return (
    <div className="settings-page fade-in">
      <div className="settings-container">
        <h1 className="settings-title">Settings</h1>
        
        <section className="settings-section card">
          <h2>Appearance</h2>
          <div className="settings-row">
            <div className="settings-info">
              <h3>Theme</h3>
              <p>Select your preferred color scheme</p>
            </div>
            <div className="theme-options">
              <label className="theme-radio">
                <input 
                  type="radio" 
                  name="theme" 
                  value="light" 
                  checked={theme === 'light'} 
                  onChange={() => setTheme('light')} 
                  id="theme-light" 
                />
                Light
              </label>
              <label className="theme-radio">
                <input 
                  type="radio" 
                  name="theme" 
                  value="dark" 
                  checked={theme === 'dark'} 
                  onChange={() => setTheme('dark')} 
                  id="theme-dark" 
                />
                Dark
              </label>
              <label className="theme-radio">
                <input 
                  type="radio" 
                  name="theme" 
                  value="system" 
                  checked={theme === 'system'} 
                  onChange={() => setTheme('system')} 
                  id="theme-system" 
                />
                System
              </label>
            </div>
          </div>
        </section>

        <section className="settings-section card">
          <h2>Notifications</h2>
          <div className="settings-row">
            <div className="settings-info">
              <h3>Default Channel</h3>
              <p>Where to send general alerts</p>
            </div>
            <select id="notif-channel">
              <option value="slack">Slack</option>
              <option value="teams">Microsoft Teams</option>
              <option value="email">Email</option>
              <option value="webhook">Webhook</option>
            </select>
          </div>
          <div className="settings-row">
            <div className="settings-info">
              <h3>Digest Frequency</h3>
              <p>How often to receive summary emails</p>
            </div>
            <select id="notif-freq">
              <option value="realtime">Real-time</option>
              <option value="hourly">Hourly</option>
              <option value="daily">Daily</option>
            </select>
          </div>
        </section>

        <section className="settings-section card">
          <h2>API Access</h2>
          <div className="settings-row">
            <div className="settings-info">
              <h3>Personal API Key</h3>
              <p>Used for programmatic access to Crossroads API</p>
            </div>
            <div className="api-key-container">
              <div className="api-key-display">
                <code>{showApiKey ? apiKey : '••••••••••••••••••••••••••••••••••••'}</code>
                <button id="toggle-key" className="btn btn--ghost btn--sm" onClick={() => setShowApiKey(!showApiKey)}>
                  {showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <button id="copy-key" className="btn btn--secondary btn--sm"><Copy size={16}/> Copy</button>
              <button id="regen-key" className="btn btn--secondary btn--sm" onClick={() => confirm('Regenerate API key? Old key will be invalidated.')}><RefreshCw size={16}/> Regenerate</button>
            </div>
          </div>
        </section>

        <section className="settings-section card">
          <h2>Account</h2>
          <div className="settings-row">
            <div className="settings-info">
              <h3>Display Name</h3>
              <input type="text" readOnly value="Admin User" id="acct-name" className="readonly-input" />
            </div>
          </div>
          <div className="settings-row">
            <div className="settings-info">
              <h3>Email</h3>
              <input type="text" readOnly value="admin@example.com" id="acct-email" className="readonly-input" />
            </div>
          </div>
          <div className="settings-row">
            <button id="manage-acct" className="btn btn--primary">Manage Account (Cognito)</button>
          </div>
        </section>
      </div>
    </div>
  );
}
