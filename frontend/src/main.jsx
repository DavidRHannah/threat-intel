import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App.jsx';

document.documentElement.setAttribute('data-theme', 
  localStorage.getItem('crossroads-theme') || 
  (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
);

createRoot(document.getElementById('root')).render(<App />);
