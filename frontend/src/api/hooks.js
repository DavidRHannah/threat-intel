import { useQuery } from '@tanstack/react-query';
import client from './client';
import { normalizeSubgraph } from './normalize';

/* ============================================
   Dashboard API Hooks
   ============================================ */

export function useStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => client.get('/dashboard/stats').then(r => r.data),
    refetchInterval: 5 * 60 * 1000, // 5 minutes
    staleTime: 2 * 60 * 1000,
  });
}

export function useTopCves(limit = 10) {
  return useQuery({
    queryKey: ['dashboard', 'top-cves', limit],
    queryFn: () => client.get('/dashboard/top-cves', { params: { limit } }).then(r => r.data),
    refetchInterval: 5 * 60 * 1000,
    staleTime: 2 * 60 * 1000,
  });
}

export function useTopActors(limit = 10) {
  return useQuery({
    queryKey: ['dashboard', 'top-actors', limit],
    queryFn: () => client.get('/dashboard/top-actors', { params: { limit } }).then(r => r.data),
    refetchInterval: 5 * 60 * 1000,
    staleTime: 2 * 60 * 1000,
  });
}

export function useTopMalware(limit = 10) {
  return useQuery({
    queryKey: ['dashboard', 'top-malware', limit],
    queryFn: () => client.get('/dashboard/top-malware', { params: { limit } }).then(r => r.data),
    refetchInterval: 5 * 60 * 1000,
    staleTime: 2 * 60 * 1000,
  });
}

export function useRecentStories(limit = 20) {
  return useQuery({
    queryKey: ['dashboard', 'recent-stories', limit],
    queryFn: () => client.get('/dashboard/recent-stories', { params: { limit } }).then(r => r.data),
    refetchInterval: 5 * 60 * 1000,
    staleTime: 2 * 60 * 1000,
  });
}

export function useTtpHeatmap() {
  return useQuery({
    queryKey: ['dashboard', 'ttp-heatmap'],
    queryFn: () => client.get('/dashboard/ttp-heatmap').then(r => r.data),
    refetchInterval: 10 * 60 * 1000,
    staleTime: 5 * 60 * 1000,
  });
}

export function useSubgraph(id) {
  return useQuery({
    queryKey: ['dashboard', 'subgraph', id],
    queryFn: () => client.get(`/dashboard/subgraph/${id}`).then(r => normalizeSubgraph(r.data)),
    enabled: !!id,
    staleTime: 5 * 60 * 1000,
  });
}

export function useSearch(query, params = {}) {
  return useQuery({
    queryKey: ['search', query, params],
    queryFn: () => client.get('/search', { params: { q: query, ...params } }).then(r => r.data),
    enabled: !!query && query.length >= 2,
    staleTime: 60 * 1000,
  });
}

/* ============================================
   Watchlist API Hooks
   ============================================ */

export function useWatchlists() {
  return useQuery({
    queryKey: ['watchlists'],
    queryFn: () => client.get('/watchlist').then(r => r.data),
    staleTime: 60 * 1000,
  });
}

export async function upsertWatchlist(id, data) {
  return client.put(`/watchlist/${id}`, data).then(r => r.data);
}

export async function deleteWatchlist(id) {
  return client.delete(`/watchlist/${id}`).then(r => r.data);
}

/* ============================================
   Briefing API Hooks
   ============================================ */

export function useBriefings() {
  return useQuery({
    queryKey: ['briefings'],
    queryFn: () => client.get('/briefings').then(r => r.data),
    staleTime: 5 * 60 * 1000,
  });
}

export function useBriefing(id) {
  return useQuery({
    queryKey: ['briefings', id],
    queryFn: () => client.get(`/briefings/${id}`).then(r => r.data),
    enabled: !!id,
    staleTime: 10 * 60 * 1000,
  });
}
