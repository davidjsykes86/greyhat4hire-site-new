const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  'https://greyhat4hire.com',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const url   = new URL(request.url);
  const mode  = url.searchParams.get('mode');
  const query = (url.searchParams.get('q') || '').trim();
  const count = Math.min(parseInt(url.searchParams.get('count') || '20'), 50);

  try {
    let payload;
    if (mode === 'kev') {
      payload = await fetchKEV();
    } else if (mode === 'cve') {
      if (!query) return jsonResponse({ error: 'Missing q param' }, 400);
      payload = await fetchByCVEId(query, env.NVD_API_KEY);
    } else if (mode === 'keyword') {
      if (!query) return jsonResponse({ error: 'Missing q param' }, 400);
      payload = await fetchByKeyword(query, count, env.NVD_API_KEY);
    } else {
      return jsonResponse({ error: 'Invalid mode' }, 400);
    }
    return jsonResponse(payload);
  } catch (err) {
    return jsonResponse({ error: err.message, cves: [], source: 'error' }, 500);
  }
}

// Maps what the card sends → CIRCL vendor/product path
// CIRCL is the primary source — no IP blocking, no rate limits
const CIRCL_MAP = {
  // Cards send these exact strings as keywords
  'google android':       'google/android',
  'apple macos':          'apple/mac_os_x',
  'apple ios':            'apple/iphone_os',
  'microsoft windows':    'microsoft/windows',
  'linux kernel':         'linux/linux_kernel',
  'apache http server':   'apache/http_server',
  'wordpress':            'wordpress/wordpress',
  'nginx':                'nginx/nginx',
  'php':                  'php/php',
  'drupal':               'drupal/drupal',
  'joomla':               'joomla/joomla',
  'openssl':              'openssl/openssl',
  'mysql':                'mysql/mysql',
  'postgresql':           'postgresql/postgresql',
  'mongodb':              'mongodb/mongodb',
  'redis':                'redis/redis',
  'oracle database':      'oracle/database',
  'cisco ios':            'cisco/ios',
  'fortios':              'fortinet/fortios',
  'pan-os':               'paloaltonetworks/pan-os',
  'junos':                'juniper/junos',
  'docker':               'docker/docker',
  'kubernetes':           'kubernetes/kubernetes',
  'jenkins':              'jenkins/jenkins',
  'node.js':              'nodejs/node.js',
  'microsoft office':     'microsoft/office',
  'microsoft exchange':   'microsoft/exchange_server',
  'microsoft sql server': 'microsoft/sql_server',
  'adobe acrobat':        'adobe/acrobat_reader',
  'google chrome':        'google/chrome',
  'mozilla firefox':      'mozilla/firefox',
  'amazon web services':  'amazon/aws',
  'zoom video':           'zoom/zoom',
  // Also handle raw terms in case user types them directly
  'android':              'google/android',
  'windows':              'microsoft/windows',
  'linux':                'linux/linux_kernel',
  'apache':               'apache/http_server',
  'chrome':               'google/chrome',
  'firefox':              'mozilla/firefox',
  'ios':                  'apple/iphone_os',
  'macos':                'apple/mac_os_x',
  'iphone':               'apple/iphone_os',
};

// NVD keyword map — only used as secondary attempt if CIRCL fails
const NVD_MAP = {
  'google android':       'android',
  'apple macos':          'macos',
  'apple ios':            'iphone os',
  'microsoft windows':    'windows',
  'linux kernel':         'linux kernel',
  'apache http server':   'apache http server',
  'microsoft exchange':   'exchange server',
  'microsoft office':     'microsoft office',
  'microsoft sql server': 'sql server',
  'amazon web services':  'amazon',
  'cisco ios':            'cisco ios',
  'fortios':              'fortios',
  'pan-os':               'pan-os',
  'adobe acrobat':        'acrobat reader',
  'google chrome':        'chrome',
  'mozilla firefox':      'firefox',
  'zoom video':           'zoom',
  'node.js':              'node.js',
  'oracle database':      'oracle database',
};

async function fetchByCVEId(cveId, apiKey) {
  const id = cveId.toUpperCase();

  // Try CIRCL first for CVE lookups — no IP blocking issues
  const circl = await circlById(id);
  if (circl) return { cves: [circl], source: 'circl' };

  // Try NVD as secondary
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`;
  const nvd = await nvdFetch(url, apiKey);
  if (nvd.ok) {
    const cves = (nvd.data.vulnerabilities || []).map(v => v.cve);
    if (cves.length) return { cves, source: 'nvd' };
  }

  return { cves: [], source: 'none', reason: 'Not found in CIRCL or NVD' };
}

async function fetchByKeyword(keyword, count, apiKey) {
  const kw = keyword.toLowerCase();
  const log = [];

  // ── Step 1: Try CIRCL (primary — no IP blocking, no rate limits) ──
  const circlPath = CIRCL_MAP[kw];
  log.push({ step: 'circl', path: circlPath || 'no mapping', kw });

  if (circlPath) {
    const cves = await circlByVendor(circlPath, count);
    log.push({ circlResults: cves.length });
    if (cves.length) return { cves, source: 'circl' };
  }

  // ── Step 2: Try NVD as secondary (may be blocked from Cloudflare IPs) ──
  const nvdTerm = NVD_MAP[kw] || keyword;
  const nvdUrl  = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(nvdTerm)}&resultsPerPage=${count}&sortBy=publishDate&sortOrder=desc`;
  const nvd     = await nvdFetch(nvdUrl, apiKey);
  log.push({ step: 'nvd', term: nvdTerm, ok: nvd.ok, reason: nvd.reason });

  if (nvd.ok) {
    const cves = (nvd.data.vulnerabilities || []).map(v => v.cve);
    if (cves.length) return { cves, source: 'nvd' };
  }

  return { cves: [], source: 'none', reason: '0 results', debug: log };
}

async function fetchKEV() {
  const res = await fetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  );
  if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
  const data = await res.json();
  return { vulnerabilities: data.vulnerabilities || [] };
}

async function nvdFetch(url, apiKey) {
  try {
    const headers = apiKey ? { apiKey } : {};
    const res = await fetch(url, { headers });
    if (res.status === 429) return { ok: false, reason: 'NVD rate limited' };
    if (res.status === 403) return { ok: false, reason: 'NVD access denied' };
    if (res.status === 404) return { ok: false, reason: 'NVD 404 no results' };
    if (!res.ok)            return { ok: false, reason: `NVD error ${res.status}` };
    return { ok: true, data: await res.json() };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

async function circlById(cveId) {
  try {
    const res = await fetch(`https://cve.circl.lu/api/cve/${cveId}`);
    if (!res.ok) return null;
    const cd = await res.json();
    return normaliseCIRCL(cd);
  } catch { return null; }
}

async function circlByVendor(path, count) {
  try {
    const res = await fetch(`https://cve.circl.lu/api/search/${path}`);
    if (!res.ok) return [];
    const data = await res.json();
    const raw  = Array.isArray(data) ? data : (data.results || []);
    return raw.slice(0, count).map(normaliseCIRCL).filter(Boolean);
  } catch { return []; }
}

function normaliseCIRCL(cd) {
  if (!cd || !cd.id) return null;
  const metrics = {};
  if (cd.cvss3)     metrics.cvssMetricV31 = [{ cvssData: { baseScore: parseFloat(cd.cvss3), vectorString: cd.cvss3_vector || '' } }];
  else if (cd.cvss) metrics.cvssMetricV2  = [{ cvssData: { baseScore: parseFloat(cd.cvss),  vectorString: cd.cvss_vector  || '' } }];
  return {
    id:             cd.id,
    published:      cd.Published    || cd.publishedDate    || '',
    lastModified:   cd.Modified     || cd.lastModifiedDate || '',
    descriptions:   [{ lang: 'en', value: cd.summary || cd.Description || 'No description.' }],
    metrics,
    references:     (cd.references || []).map(u => ({ url: u })),
    weaknesses:     [],
    configurations: [],
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...CORS_HEADERS,
    },
  });
}
