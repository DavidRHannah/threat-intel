import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

const client = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: attach the Cognito Hosted UI id_token stored by AuthCallbackPage.
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('crossroads-auth-token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor: an expired/invalid token gets a fresh Hosted UI round-trip.
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('crossroads-auth-token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default client;
