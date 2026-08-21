/**
 * Mock data for development. Mirrors the shapes returned by the Read API.
 * Used when VITE_USE_MOCKS=true or when the API is unavailable.
 */

export const mockStats = {
  total_cves: 1247,
  critical_cves: 23,
  high_cves: 89,
  medium_cves: 342,
  low_cves: 793,
  active_exploits: 8,
  total_actors: 156,
  total_malware: 234,
  total_ttps: 612,
  total_iocs: 4521,
  total_articles: 8934,
  articles_today: 47,
  articles_week: 342,
  severity_distribution: {
    critical: 23, high: 89, medium: 342, low: 793, unknown: 0,
  },
  trend_deltas: {
    articles_today: -12,
  },
};

export const mockTopCves = [
  { id: 'n1', cve_id: 'CVE-2026-31245', description: 'Remote code execution in Apache HTTP Server mod_rewrite via crafted URI-path', cvss_score: 9.8, epss_score: 0.94, exploited_in_wild: true, severity_score: 0.96, severity_band: 'critical', relevance_score: 0.91, published_date: '2026-08-09T00:00:00Z', exploiter_count: 4 },
  { id: 'n2', cve_id: 'CVE-2026-28819', description: 'Privilege escalation in Linux kernel via use-after-free in nf_tables', cvss_score: 9.1, epss_score: 0.87, exploited_in_wild: true, severity_score: 0.93, severity_band: 'critical', relevance_score: 0.88, published_date: '2026-08-07T00:00:00Z', exploiter_count: 3 },
  { id: 'n3', cve_id: 'CVE-2026-30102', description: 'SQL injection in Fortinet FortiGate SSL-VPN login endpoint', cvss_score: 9.6, epss_score: 0.79, exploited_in_wild: true, severity_score: 0.91, severity_band: 'critical', relevance_score: 0.85, published_date: '2026-08-06T00:00:00Z', exploiter_count: 2 },
  { id: 'n4', cve_id: 'CVE-2026-29554', description: 'Authentication bypass in Ivanti Connect Secure via SAML assertion manipulation', cvss_score: 8.8, epss_score: 0.72, exploited_in_wild: false, severity_score: 0.82, severity_band: 'critical', relevance_score: 0.79, published_date: '2026-08-05T00:00:00Z', exploiter_count: 1 },
  { id: 'n5', cve_id: 'CVE-2026-27891', description: 'Deserialization RCE in VMware vCenter Server', cvss_score: 8.5, epss_score: 0.65, exploited_in_wild: false, severity_score: 0.74, severity_band: 'high', relevance_score: 0.71, published_date: '2026-08-04T00:00:00Z', exploiter_count: 0 },
  { id: 'n6', cve_id: 'CVE-2026-31001', description: 'Path traversal in Palo Alto PAN-OS GlobalProtect', cvss_score: 8.2, epss_score: 0.58, exploited_in_wild: false, severity_score: 0.69, severity_band: 'high', relevance_score: 0.65, published_date: '2026-08-03T00:00:00Z', exploiter_count: 1 },
  { id: 'n7', cve_id: 'CVE-2026-26743', description: 'Cross-site scripting in Microsoft Exchange OWA attachment handling', cvss_score: 6.9, epss_score: 0.34, exploited_in_wild: false, severity_score: 0.48, severity_band: 'medium', relevance_score: 0.52, published_date: '2026-08-02T00:00:00Z', exploiter_count: 0 },
  { id: 'n8', cve_id: 'CVE-2026-30887', description: 'Information disclosure via SNMP misconfiguration in Cisco IOS XE', cvss_score: 5.3, epss_score: 0.21, exploited_in_wild: false, severity_score: 0.35, severity_band: 'low', relevance_score: 0.38, published_date: '2026-08-01T00:00:00Z', exploiter_count: 0 },
];

export const mockTopActors = [
  { id: 'a1', name: 'APT29 (Cozy Bear)', mitre_id: 'G0016', origin_country: 'Russia', motivation: 'espionage', relevance_score: 0.94, confidence: 1.0, ttp_count: 48, malware_count: 12, active_since: '2008' },
  { id: 'a2', name: 'Lazarus Group', mitre_id: 'G0032', origin_country: 'North Korea', motivation: 'financial', relevance_score: 0.91, confidence: 1.0, ttp_count: 52, malware_count: 18, active_since: '2009' },
  { id: 'a3', name: 'APT28 (Fancy Bear)', mitre_id: 'G0007', origin_country: 'Russia', motivation: 'espionage', relevance_score: 0.87, confidence: 1.0, ttp_count: 41, malware_count: 9, active_since: '2004' },
  { id: 'a4', name: 'Volt Typhoon', mitre_id: 'G1017', origin_country: 'China', motivation: 'espionage', relevance_score: 0.84, confidence: 1.0, ttp_count: 22, malware_count: 3, active_since: '2021' },
  { id: 'a5', name: 'Scattered Spider', mitre_id: null, origin_country: 'Unknown', motivation: 'financial', relevance_score: 0.81, confidence: 0.85, ttp_count: 15, malware_count: 5, active_since: '2022' },
  { id: 'a6', name: 'Sandworm', mitre_id: 'G0034', origin_country: 'Russia', motivation: 'sabotage', relevance_score: 0.78, confidence: 1.0, ttp_count: 38, malware_count: 14, active_since: '2009' },
];

export const mockTopMalware = [
  { id: 'm1', name: 'Cobalt Strike', mitre_id: 'S0154', malware_type: 'tool', relevance_score: 0.92, confidence: 1.0, actor_count: 28, platform_count: 3 },
  { id: 'm2', name: 'Mimikatz', mitre_id: 'S0002', malware_type: 'tool', relevance_score: 0.88, confidence: 1.0, actor_count: 35, platform_count: 1 },
  { id: 'm3', name: 'QakBot', mitre_id: 'S0650', malware_type: 'backdoor', relevance_score: 0.79, confidence: 1.0, actor_count: 5, platform_count: 1 },
  { id: 'm4', name: 'AsyncRAT', mitre_id: null, malware_type: 'rat', relevance_score: 0.74, confidence: 0.9, actor_count: 8, platform_count: 2 },
  { id: 'm5', name: 'BlackCat (ALPHV)', mitre_id: 'S1068', malware_type: 'ransomware', relevance_score: 0.71, confidence: 1.0, actor_count: 3, platform_count: 2 },
];

export const mockRecentStories = [
  { id: 's1', cluster_id: 'sc-001', headline: 'Critical Apache HTTP Server RCE actively exploited in the wild', article_count: 12, created_at: '2026-08-11T14:30:00Z', entities: [{ type: 'cve', id: 'CVE-2026-31245' }, { type: 'actor', name: 'APT29' }] },
  { id: 's2', cluster_id: 'sc-002', headline: 'Lazarus Group targets crypto exchanges with new macOS backdoor', article_count: 8, created_at: '2026-08-11T11:15:00Z', entities: [{ type: 'actor', name: 'Lazarus Group' }, { type: 'malware', name: 'TraderTraitor' }] },
  { id: 's3', cluster_id: 'sc-003', headline: 'Volt Typhoon leverages living-off-the-land techniques against US infrastructure', article_count: 15, created_at: '2026-08-11T08:45:00Z', entities: [{ type: 'actor', name: 'Volt Typhoon' }, { type: 'ttp', id: 'T1059' }] },
  { id: 's4', cluster_id: 'sc-004', headline: 'Linux kernel nf_tables privilege escalation zero-day confirmed by CISA KEV', article_count: 6, created_at: '2026-08-10T22:00:00Z', entities: [{ type: 'cve', id: 'CVE-2026-28819' }] },
  { id: 's5', cluster_id: 'sc-005', headline: 'FortiGate SSL-VPN SQL injection used in mass exploitation campaign', article_count: 9, created_at: '2026-08-10T16:30:00Z', entities: [{ type: 'cve', id: 'CVE-2026-30102' }] },
  { id: 's6', cluster_id: 'sc-006', headline: 'New Scattered Spider social engineering tactics target cloud SSO providers', article_count: 4, created_at: '2026-08-10T12:00:00Z', entities: [{ type: 'actor', name: 'Scattered Spider' }, { type: 'ttp', id: 'T1566' }] },
  { id: 's7', cluster_id: 'sc-007', headline: 'QakBot resurfaces with updated C2 infrastructure after FBI takedown', article_count: 7, created_at: '2026-08-10T09:00:00Z', entities: [{ type: 'malware', name: 'QakBot' }] },
  { id: 's8', cluster_id: 'sc-008', headline: 'CISA adds three CVEs to Known Exploited Vulnerabilities catalog', article_count: 5, created_at: '2026-08-09T20:00:00Z', entities: [{ type: 'cve', id: 'CVE-2026-31245' }, { type: 'cve', id: 'CVE-2026-28819' }] },
];

export const mockTtpHeatmap = {
  tactics: [
    { id: 'TA0043', name: 'Reconnaissance' },
    { id: 'TA0042', name: 'Resource Development' },
    { id: 'TA0001', name: 'Initial Access' },
    { id: 'TA0002', name: 'Execution' },
    { id: 'TA0003', name: 'Persistence' },
    { id: 'TA0004', name: 'Privilege Escalation' },
    { id: 'TA0005', name: 'Defense Evasion' },
    { id: 'TA0006', name: 'Credential Access' },
    { id: 'TA0007', name: 'Discovery' },
    { id: 'TA0008', name: 'Lateral Movement' },
    { id: 'TA0009', name: 'Collection' },
    { id: 'TA0011', name: 'Command and Control' },
    { id: 'TA0010', name: 'Exfiltration' },
    { id: 'TA0040', name: 'Impact' },
  ],
  techniques: [
    { id: 'T1566', name: 'Phishing', tactic: 'TA0001', heat: 0.92, top_exploiters: ['APT29', 'Lazarus Group', 'Scattered Spider'], exploiter_count: 12 },
    { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'TA0002', heat: 0.88, top_exploiters: ['APT28', 'Volt Typhoon', 'Sandworm'], exploiter_count: 18 },
    { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'TA0003', heat: 0.45, top_exploiters: ['APT29'], exploiter_count: 5 },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'TA0004', heat: 0.85, top_exploiters: ['Lazarus Group', 'Sandworm'], exploiter_count: 8 },
    { id: 'T1070', name: 'Indicator Removal', tactic: 'TA0005', heat: 0.62, top_exploiters: ['APT29', 'Volt Typhoon'], exploiter_count: 9 },
    { id: 'T1003', name: 'OS Credential Dumping', tactic: 'TA0006', heat: 0.79, top_exploiters: ['APT28', 'Lazarus Group'], exploiter_count: 14 },
    { id: 'T1082', name: 'System Information Discovery', tactic: 'TA0007', heat: 0.55, top_exploiters: ['Volt Typhoon'], exploiter_count: 11 },
    { id: 'T1021', name: 'Remote Services', tactic: 'TA0008', heat: 0.71, top_exploiters: ['APT29', 'Sandworm'], exploiter_count: 7 },
    { id: 'T1005', name: 'Data from Local System', tactic: 'TA0009', heat: 0.48, top_exploiters: ['Lazarus Group'], exploiter_count: 6 },
    { id: 'T1071', name: 'Application Layer Protocol', tactic: 'TA0011', heat: 0.83, top_exploiters: ['APT29', 'APT28', 'Lazarus Group'], exploiter_count: 16 },
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'TA0010', heat: 0.38, top_exploiters: ['APT29'], exploiter_count: 4 },
    { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'TA0040', heat: 0.67, top_exploiters: ['Sandworm', 'BlackCat'], exploiter_count: 6 },
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'TA0001', heat: 0.90, top_exploiters: ['APT29', 'Volt Typhoon', 'Lazarus Group'], exploiter_count: 10 },
    { id: 'T1055', name: 'Process Injection', tactic: 'TA0005', heat: 0.73, top_exploiters: ['Lazarus Group', 'APT28'], exploiter_count: 11 },
    { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'TA0005', heat: 0.68, top_exploiters: ['APT29', 'Sandworm'], exploiter_count: 13 },
    { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'TA0003', heat: 0.52, top_exploiters: ['APT28'], exploiter_count: 7 },
    { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'TA0011', heat: 0.76, top_exploiters: ['APT29', 'Lazarus Group'], exploiter_count: 15 },
    { id: 'T1078', name: 'Valid Accounts', tactic: 'TA0001', heat: 0.81, top_exploiters: ['Volt Typhoon', 'Scattered Spider'], exploiter_count: 9 },
    { id: 'T1595', name: 'Active Scanning', tactic: 'TA0043', heat: 0.44, top_exploiters: ['Volt Typhoon'], exploiter_count: 3 },
    { id: 'T1588', name: 'Obtain Capabilities', tactic: 'TA0042', heat: 0.35, top_exploiters: ['Lazarus Group'], exploiter_count: 4 },
    { id: 'T1110', name: 'Brute Force', tactic: 'TA0006', heat: 0.58, top_exploiters: ['APT28', 'Scattered Spider'], exploiter_count: 8 },
    { id: 'T1569', name: 'System Services', tactic: 'TA0002', heat: 0.41, top_exploiters: ['Sandworm'], exploiter_count: 5 },
    { id: 'T1562', name: 'Impair Defenses', tactic: 'TA0005', heat: 0.77, top_exploiters: ['APT29', 'Volt Typhoon', 'Sandworm'], exploiter_count: 10 },
    { id: 'T1557', name: 'Adversary-in-the-Middle', tactic: 'TA0006', heat: 0.31, top_exploiters: ['APT28'], exploiter_count: 3 },
  ],
};

export const mockSubgraph = {
  node: { id: 'n1', type: 'cve', cve_id: 'CVE-2026-31245', description: 'Remote code execution in Apache HTTP Server mod_rewrite', cvss_score: 9.8, epss_score: 0.94, exploited_in_wild: true, severity_score: 0.96, severity_band: 'critical', relevance_score: 0.91 },
  neighbors: [
    { id: 'a1', type: 'threat_actor', name: 'APT29 (Cozy Bear)', relevance_score: 0.94 },
    { id: 'a2', type: 'threat_actor', name: 'Lazarus Group', relevance_score: 0.91 },
    { id: 'm1', type: 'malware_family', name: 'Cobalt Strike', relevance_score: 0.92 },
    { id: 't1', type: 'ttp', name: 'Exploit Public-Facing Application', mitre_id: 'T1190', tactic: 'Initial Access' },
    { id: 'i1', type: 'ioc', value: '192.168.112.3', ioc_type: 'ip' },
    { id: 'i2', type: 'ioc', value: 'malware-c2.evil.com', ioc_type: 'domain' },
    { id: 'art1', type: 'article', title: 'Apache HTTP Server RCE CVE-2026-31245 analysis', source: 'NVD' },
  ],
  edges: [
    { source: 'n1', target: 'a1', type: 'EXPLOITED_BY', confidence: 0.95, origin: ['authoritative'] },
    { source: 'n1', target: 'a2', type: 'EXPLOITED_BY', confidence: 0.82, origin: ['inferred'] },
    { source: 'n1', target: 'm1', type: 'EXPLOITED_BY', confidence: 0.88, origin: ['inferred'] },
    { source: 'n1', target: 't1', type: 'USES', confidence: 1.0, origin: ['authoritative'] },
    { source: 'a1', target: 'i1', type: 'ASSOCIATED_WITH', confidence: 0.75, origin: ['inferred'] },
    { source: 'm1', target: 'i2', type: 'COMMUNICATES_WITH', confidence: 0.90, origin: ['authoritative'] },
    { source: 'art1', target: 'n1', type: 'MENTIONS', confidence: 0.98, origin: ['authoritative'] },
  ],
};

export const mockBriefings = [
  { briefing_id: 'br-001', generated_at: '2026-08-11T06:00:00Z', period_start: '2026-08-10T00:00:00Z', period_end: '2026-08-11T00:00:00Z', delivery_status: 'sent', cited_sources: ['src-1', 'src-2', 'src-3'] },
  { briefing_id: 'br-002', generated_at: '2026-08-10T06:00:00Z', period_start: '2026-08-09T00:00:00Z', period_end: '2026-08-10T00:00:00Z', delivery_status: 'sent', cited_sources: ['src-4', 'src-5'] },
  { briefing_id: 'br-003', generated_at: '2026-08-09T06:00:00Z', period_start: '2026-08-08T00:00:00Z', period_end: '2026-08-09T00:00:00Z', delivery_status: 'sent', cited_sources: ['src-6', 'src-7', 'src-8'] },
];

export const mockBriefingDetail = {
  briefing_id: 'br-001',
  generated_at: '2026-08-11T06:00:00Z',
  period_start: '2026-08-10T00:00:00Z',
  period_end: '2026-08-11T00:00:00Z',
  delivery_status: 'sent',
  cited_sources: ['src-1', 'src-2', 'src-3'],
  body_md: `# Daily Threat Intelligence Briefing\n*Period: August 10–11, 2026*\n\n## Critical Highlights\n\n### 1. Apache HTTP Server RCE (CVE-2026-31245) — Active Exploitation\nA critical remote code execution vulnerability in Apache HTTP Server's mod_rewrite module is under **active exploitation** by at least four threat actor groups including APT29 and Lazarus Group [src-1]. The vulnerability (CVSS 9.8, EPSS 0.94) was added to CISA's Known Exploited Vulnerabilities catalog on August 9. Organizations running Apache HTTP Server 2.4.x should apply patches immediately.\n\n### 2. Linux Kernel nf_tables Zero-Day (CVE-2026-28819)\nA use-after-free vulnerability in the Linux kernel's nf_tables subsystem enables local privilege escalation [src-2]. Three threat groups have been observed leveraging this vulnerability in targeted attacks. CISA KEV listing is pending.\n\n### 3. Volt Typhoon Continues Infrastructure Targeting\nVolt Typhoon has expanded living-off-the-land operations against US critical infrastructure, leveraging valid accounts and command-line interfaces to maintain persistent access [src-3].\n\n## Trending TTPs\n- **T1566 Phishing** — Heat: 0.92 (12 active exploiters)\n- **T1190 Exploit Public-Facing Application** — Heat: 0.90 (10 active exploiters)\n- **T1059 Command and Scripting Interpreter** — Heat: 0.88 (18 active exploiters)\n\n## Recommended Actions\n1. Patch Apache HTTP Server immediately\n2. Monitor for nf_tables exploitation indicators\n3. Review network for Volt Typhoon TTPs\n`,
};

export const mockWatchlists = [
  {
    subscriber_id: 'user-001',
    watchlist_id: 'wl-001',
    name: 'Critical Infrastructure',
    selectors: [
      { type: 'actor', name: 'Volt Typhoon' },
      { type: 'actor', name: 'Sandworm' },
      { type: 'ttp', mitre_id: 'T1190' },
    ],
    boost: 1.5,
    alert_thresholds: { severity_gte: 0.8, relevance_gte: 0.7 },
    routes: [{ channel: 'slack', webhook_url: 'https://hooks.slack.com/...' }],
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-08-01T00:00:00Z',
  },
  {
    subscriber_id: 'user-001',
    watchlist_id: 'wl-002',
    name: 'Apache Stack',
    selectors: [
      { type: 'product', vendor: 'apache', product: '*' },
      { type: 'cve', pattern: 'CVE-2026-3*' },
    ],
    boost: 2.0,
    alert_thresholds: { severity_gte: 0.6, kev_listed: true },
    routes: [{ channel: 'webhook', url: 'https://my-siem.internal/webhook' }],
    created_at: '2026-07-15T00:00:00Z',
    updated_at: '2026-08-05T00:00:00Z',
  },
];
