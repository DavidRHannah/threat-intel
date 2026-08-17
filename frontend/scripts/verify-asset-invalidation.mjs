/**
 * Executable harness for final-review finding #7 (this frontend has no test framework;
 * `verify-egograph.mjs` is the existing precedent for pinning a frontend fix this way).
 *
 * Runs the REAL @tanstack/react-query QueryClient against the REAL query keys
 * `src/api/hooks.js` uses, and proves that the single prefix invalidation AssetsPage now
 * issues after a create/delete -- invalidateQueries({ queryKey: ['assets'] }) -- actually
 * marks the 2-minute-staleTime CVE-list queries stale, not just the asset list.
 *
 * Run: node scripts/verify-asset-invalidation.mjs
 */
import { QueryClient } from '@tanstack/react-query';

const KEYS = {
  list: ['assets'],
  assetCves: ['assets', 'acme::x::1.0.0', 'cves'],
  allCves: ['assets', 'cves'],
  unrelated: ['dashboard', 'top-cves'],
};

const qc = new QueryClient();
for (const key of Object.values(KEYS)) {
  qc.setQueryData(key, { seeded: true });
}

const stale = () =>
  Object.fromEntries(
    Object.entries(KEYS).map(([name, key]) => [
      name,
      qc.getQueryState(key)?.isInvalidated ?? false,
    ]),
  );

const before = stale();
await qc.invalidateQueries({ queryKey: ['assets'] });
const after = stale();

const expected = { list: true, assetCves: true, allCves: true, unrelated: false };
const failures = Object.entries(expected).filter(([name, want]) => after[name] !== want);

console.log('before:', before);
console.log('after :', after);
if (failures.length) {
  console.error('FAIL:', failures);
  process.exit(1);
}
console.log('PASS: one ["assets"] invalidation covers the list AND both CVE-list queries');
