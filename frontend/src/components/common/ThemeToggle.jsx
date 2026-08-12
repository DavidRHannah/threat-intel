import { useTheme } from '../../hooks/useTheme';
import { Sun, Moon } from 'lucide-react';

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  
  return (
    <button 
      id="theme-toggle-btn"
      onClick={toggleTheme} 
      className="btn btn--ghost"
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '40px',
        height: '40px',
        borderRadius: 'var(--radius-full)',
        transition: 'all var(--transition-base)'
      }}
    >
      {theme === 'dark' ? (
        <Sun size={20} style={{ transition: 'transform var(--transition-base)' }} />
      ) : (
        <Moon size={20} style={{ transition: 'transform var(--transition-base)' }} />
      )}
    </button>
  );
}
