const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  'https://greyhat4hire.com',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });

  const url   = new URL(request.url);
  const mode  = url.searchParams.get('mode');
  const query = (url.searchParams.get('q') || '').trim();
  const count = Math.min(parseInt(url.searchParams.get('count') || '20'), 50);

  try {
    let payload;
    if      (mode === 'kev')     payload = await fetchKEV();
    else if (mode === 'cve')     payload = await fetchByCVEId(query, env.GITHUB_TOKEN);
    else if (mode === 'keyword') payload = await fetchByKeyword(query, count, env.GITHUB_TOKEN);
    else return jsonResponse({ error: 'Invalid mode' }, 400);
    return jsonResponse(payload);
  } catch (err) {
    return jsonResponse({ error: err.message, cves: [], source: 'error' }, 500);
  }
}

// ── Maps product card keywords → GitHub Advisory ecosystem
const GH_ECOSYSTEM = {
  'wordpress':            'composer',
  'drupal':               'composer',
  'joomla':               'composer',
  'php':                  'composer',
  'node.js':              'npm',
  'python':               'pip',
  'ruby':                 'rubygems',
  'java':                 'maven',
  'jenkins':              'maven',
  'kubernetes':           'actions',
  'docker':               'actions',
  'rust':                 'crates.io',
  'golang':               'go',
  'mysql':                'maven',
  'redis':                'npm',
};

// ── Maps product card keywords → OSV.dev ecosystem
const OSV_ECOSYSTEM = {
  'google android':       'Android',
  'node.js':              'npm',
  'php':                  'Packagist',
  'wordpress':            'Packagist',
  'drupal':               'Packagist',
  'python':               'PyPI',
  'ruby':                 'RubyGems',
  'rust':                 'crates.io',
  'golang':               'Go',
  'kubernetes':           'Go',
  'docker':               'Go',
};

// ── Maps product card keywords → search terms for GitHub Advisory free-text
const GH_SEARCH_TERMS = {
  'google android':       'android',
  'apple macos':          'macos',
  'apple ios':            'ios iphone',
  'microsoft windows':    'windows',
  'linux kernel':         'linux kernel',
  'apache http server':   'apache httpd',
  'microsoft exchange':   'exchange server',
  'microsoft office':     'microsoft office',
  'microsoft sql server': 'sql server',
  'amazon web services':  'aws amazon',
  'cisco ios':            'cisco ios',
  'fortios':              'fortinet fortios',
  'pan-os':               'paloalto pan-os',
  'adobe acrobat':        'adobe acrobat',
  'google chrome':        'chromium chrome',
  'mozilla firefox':      'firefox mozilla',
  'zoom video':           'zoom',
  'oracle database':      'oracle database',
  'openssl':              'openssl',
  'nginx':                'nginx',
  'mysql':                'mysql',
  'postgresql':           'postgresql',
  'mongodb':              'mongodb',
  'redis':                'redis',
};

// ─────────────────────────────────────────
//  Fetch by exact CVE ID
// ─────────────────────────────────────────
async function fetchByCVEId(cveId, githubToken) {
  if (!cveId) return { cves: [], source: 'none', reason: 'Missing CVE ID' };
  const id = cveId.toUpperCase();

  // 1. GitHub Advisory — lookup by CVE ID (very reliable)
  const ghCves = await ghAdvisoryByCVE(id, githubToken);
  if (ghCves.length) return { cves: ghCves, source: 'github' };

  // 2. OSV.dev — lookup by CVE ID
  const osvCves = await osvById(id);
  if (osvCves.length) return { cves: osvCves, source: 'osv' };

  return { cves: [], source: 'none', reason: `No data found for ${id}` };
}

// ─────────────────────────────────────────
//  Fetch by product keyword
// ─────────────────────────────────────────
async function fetchByKeyword(keyword, count, githubToken) {
  const kw = keyword.toLowerCase();
  const log = [];

  // 1. OSV by ecosystem (best for open source products)
  const osvEco = OSV_ECOSYSTEM[kw];
  if (osvEco) {
    const cves = await osvByEcosystem(osvEco, count);
    log.push({ source: 'osv-ecosystem', ecosystem: osvEco, count: cves.length });
    if (cves.length) return { cves, source: 'osv', debug: log };
  }

  // 2. GitHub Advisory — try ecosystem filter first
  const ghEco = GH_ECOSYSTEM[kw];
  if (ghEco) {
    const cves = await ghAdvisoryByEcosystem(ghEco, count, githubToken);
    log.push({ source: 'gh-ecosystem', ecosystem: ghEco, count: cves.length });
    if (cves.length) return { cves, source: 'github', debug: log };
  }

  // 3. GitHub Advisory — free text search
  const searchTerm = GH_SEARCH_TERMS[kw] || keyword;
  const ghCves = await ghAdvisorySearch(searchTerm, count, githubToken);
  log.push({ source: 'gh-search', term: searchTerm, count: ghCves.length });
  if (ghCves.length) return { cves: ghCves, source: 'github', debug: log };

  // 4. OSV free text (last resort)
  const osvCves = await osvByKeyword(keyword, count);
  log.push({ source: 'osv-keyword', count: osvCves.length });
  if (osvCves.length) return { cves: osvCves, source: 'osv', debug: log };

  return { cves: [], source: 'none', reason: '0 results', debug: log };
}

// ─────────────────────────────────────────
//  GitHub Advisory API helpers
// ─────────────────────────────────────────
function ghHeaders(token) {
  const h = { 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (token) h['Authorization'] = `Bearer ${token}`;
  return h;
}

async function ghAdvisoryByCVE(cveId, token) {
  try {
    const res = await fetch(`https://api.github.com/advisories?cve_id=${encodeURIComponent(cveId)}&per_page=5`, { headers: ghHeaders(token) });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data.map(normaliseGH).filter(Boolean) : [];
  } catch { return []; }
}

async function ghAdvisoryByEcosystem(ecosystem, count, token) {
  try {
    const res = await fetch(`https://api.github.com/advisories?ecosystem=${encodeURIComponent(ecosystem)}&per_page=${count}`, { headers: ghHeaders(token) });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data.map(normaliseGH).filter(Boolean) : [];
  } catch { return []; }
}

async function ghAdvisorySearch(term, count, token) {
  try {
    const res = await fetch(`https://api.github.com/advisories?q=${encodeURIComponent(term)}&per_page=${count}`, { headers: ghHeaders(token) });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data.map(normaliseGH).filter(Boolean) : [];
  } catch { return []; }
}

// Convert GitHub Advisory format → NVD-compatible shape for the frontend
function normaliseGH(adv) {
  if (!adv || !adv.ghsa_id) return null;
  const cveId = adv.cve_id || adv.ghsa_id;
  const aff   = adv.vulnerabilities?.[0];
  const sev   = (adv.severity || '').toUpperCase();
  const scoreMap = { CRITICAL: 9.5, HIGH: 7.5, MODERATE: 5.5, MEDIUM: 5.5, LOW: 2.0 };
  const score = adv.cvss?.score || scoreMap[sev] || null;
  const metrics = {};
  if (score) metrics.cvssMetricV31 = [{ cvssData: { baseScore: score, vectorString: adv.cvss?.vector_string || '' } }];
  return {
    id:             cveId,
    ghsa_id:        adv.ghsa_id,
    published:      adv.published_at || '',
    lastModified:   adv.updated_at   || '',
    descriptions:   [{ lang: 'en', value: adv.summary || adv.description || 'No description.' }],
    metrics,
    references:     (adv.references || []).map(u => ({ url: u })),
    weaknesses:     (adv.cwes || []).map(c => ({ description: [{ value: c.cwe_id }] })),
    configurations: [],
    _ghPackage:     aff?.package?.name || null,
    _ghEcosystem:   aff?.package?.ecosystem || null,
  };
}

// ─────────────────────────────────────────
//  OSV.dev API helpers
// ─────────────────────────────────────────
async function osvById(cveId) {
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version: '', package: { name: cveId } }),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.vulns || []).slice(0, 5).map(normaliseOSV).filter(Boolean);
  } catch { return []; }
}

async function osvByEcosystem(ecosystem, count) {
  // OSV doesn't have a direct "list by ecosystem" endpoint
  // Use the batch query with common package names per ecosystem
  return [];
}

async function osvByKeyword(keyword, count) {
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: keyword } }),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.vulns || []).slice(0, count).map(normaliseOSV).filter(Boolean);
  } catch { return []; }
}

// Convert OSV format → NVD-compatible shape
function normaliseOSV(v) {
  if (!v || !v.id) return null;
  // Find CVE alias if present
  const cveId = (v.aliases || []).find(a => a.startsWith('CVE-')) || v.id;
  const score = v.database_specific?.severity === 'CRITICAL' ? 9.5
    : v.database_specific?.severity === 'HIGH' ? 7.5
    : v.database_specific?.severity === 'MEDIUM' ? 5.5
    : v.database_specific?.severity === 'LOW' ? 2.0 : null;
  const metrics = {};
  if (score) metrics.cvssMetricV31 = [{ cvssData: { baseScore: score, vectorString: '' } }];
  const desc = v.details || v.summary || 'No description.';
  return {
    id:             cveId,
    published:      v.published || '',
    lastModified:   v.modified  || '',
    descriptions:   [{ lang: 'en', value: desc }],
    metrics,
    references:     (v.references || []).map(r => ({ url: r.url })),
    weaknesses:     [],
    configurations: [],
  };
}

// ─────────────────────────────────────────
//  CISA KEV
// ─────────────────────────────────────────
async function fetchKEV() {
  const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
  const data = await res.json();
  return { vulnerabilities: data.vulnerabilities || [] };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS_HEADERS },
  });
}
