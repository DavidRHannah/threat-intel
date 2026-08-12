import { StrictMode, lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from './hooks/useTheme';
import { AppShell } from './components/layout/AppShell';
import './App.css';

/* Lazy-loaded pages for code splitting */
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const HeatmapPage = lazy(() => import('./pages/HeatmapPage'));
const ThreatsPage = lazy(() => import('./pages/ThreatsPage'));
const ActorsPage = lazy(() => import('./pages/ActorsPage'));
const SearchPage = lazy(() => import('./pages/SearchPage'));
const WatchlistsPage = lazy(() => import('./pages/WatchlistsPage'));
const BriefingsPage = lazy(() => import('./pages/BriefingsPage'));
const EntityDetailPage = lazy(() => import('./pages/EntityDetailPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      refetchOnWindowFocus: false,
    },
  },
});

function PageLoader() {
  return (
    <div className="page-loader">
      <div className="page-loader__spinner" />
      <p className="page-loader__text">Loading...</p>
    </div>
  );
}

export default function App() {
  return (
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <BrowserRouter>
            <Routes>
              <Route element={<AppShell />}>
                <Route
                  index
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <DashboardPage />
                    </Suspense>
                  }
                />
                <Route
                  path="heatmap"
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <HeatmapPage />
                    </Suspense>
                  }
                />
                <Route
                  path="threats"
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <ThreatsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="actors"
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <ActorsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="search"
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <SearchPage />
                    </Suspense>
                  }
                />
                <Route
                  path="watchlists"
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <WatchlistsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="briefings"
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <BriefingsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="entity/:type/:id"
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <EntityDetailPage />
                    </Suspense>
                  }
                />
                <Route
                  path="settings"
                  element={
                    <Suspense fallback={<PageLoader />}>
                      <SettingsPage />
                    </Suspense>
                  }
                />
              </Route>
            </Routes>
          </BrowserRouter>
        </ThemeProvider>
      </QueryClientProvider>
    </StrictMode>
  );
}
