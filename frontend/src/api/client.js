import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

const client = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: attach Cognito JWT if available
client.interceptors.request.use((config) => {
  // TODO: Replace with Amplify Auth token retrieval
  const token = localStorage.getItem('crossroads-auth-token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor: handle auth errors
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // TODO: Redirect to Cognito login
      console.warn('Authentication required');
    }
    return Promise.reject(error);
  }
);

export default client;
