import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

export default function AuthCallbackPage() {
  const navigate = useNavigate();
  const [error, setError] = useState(null);

  useEffect(() => {
    // Cognito's implicit grant returns the token in the URL fragment, not a query string,
    // so it never reaches the server -- read window.location.hash directly.
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    const idToken = params.get('id_token');
    if (!idToken) {
      setError('No token returned from Cognito. Check VITE_COGNITO_* env vars.');
      return;
    }
    localStorage.setItem('crossroads-auth-token', idToken);
    navigate('/', { replace: true });
  }, [navigate]);

  if (error) {
    return <div className="page-container">{error}</div>;
  }
  return <div className="page-container">Signing in…</div>;
}
