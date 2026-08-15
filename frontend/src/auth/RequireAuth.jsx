import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';

export function RequireAuth() {
  const token = localStorage.getItem('crossroads-auth-token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}
