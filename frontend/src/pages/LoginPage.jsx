import React from 'react';
import './LoginPage.css';

function hostedUiLoginUrl() {
  const domain = import.meta.env.VITE_COGNITO_DOMAIN;
  const clientId = import.meta.env.VITE_COGNITO_CLIENT_ID;
  const redirectUri = import.meta.env.VITE_COGNITO_REDIRECT_URI;
  const params = new URLSearchParams({
    response_type: 'token',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid email',
  });
  return `https://${domain}/login?${params.toString()}`;
}

export default function LoginPage() {
  return (
    <div className="login-page fade-in">
      <div className="login-card card">
        <h1>Crossroads</h1>
        <p>Sign in to view the threat intelligence dashboard.</p>
        <a className="btn btn--primary" href={hostedUiLoginUrl()} id="login-with-cognito">
          Sign in
        </a>
      </div>
    </div>
  );
}
