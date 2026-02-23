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

const NVD_KEYWORD_MAP = {
  'google android':       ['android'],
  'apple macos':          ['macos', 'mac os x'],
  'apple ios':            ['iphone os', 'ios'],
  'microsoft windows':    ['windows 10', 'windows 11', 'windows server'],
  'linux kernel':         ['linux kernel'],
  'apache http server':   ['apache http server', 'apache httpd'],
  'microsoft exchange':   ['exchange server'],
  'microsoft office':     ['microsoft office', 'office 365'],
  'microsoft sql server': ['sql server'],
  'amazon web services':  ['aws', 'amazon'],
  'cisco ios':            ['cisco ios', 'cisco'],
  'fortios':              ['fortios', 'fortigate'],
  'pan-os':               ['pan-os', 'palo alto'],
  'adobe acrobat':        ['acrobat reader', 'adobe acrobat'],
  'google chrome':        ['chrome'],
  'mozilla firefox':      ['firefox'],
  'zoom video':           ['zoom'],
  'node.js':              ['node.js', 'nodejs'],
  'oracle database':      ['oracle database', 'oracle db'],
};

const CIRCL_VENDOR_MAP = {
  'wordpress':            'wordpress/wordpress',
  'apache http server':   'apache/http_server',
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
  'microsoft windows':    'microsoft/windows',
  'linux kernel':         'linux/linux_kernel',
  'apple macos':          'apple/mac_os_x',
  'apple ios':            'apple/iphone_os',
  'google android':       'google/android',
  'cisco ios':            'cisco/ios',
  'fortios':              'fortinet/fortios',
  'pan-os':               'paloaltonetworks/pan-os',
  'docker':               'docker/docker',
  'kubernetes':           'kubernetes/kubernetes',
  'jenkins':              'jenkins/jenkins',
  'node.js':              'nodejs/node.js',
  'microsoft office':     'microsoft/office',
  'microsoft exchange':   'microsoft/exchange_server',
  'adobe acrobat':        'adobe/acrobat_reader',
  'google chrome':        'google/chrome',
  'mozilla firefox':      'mozilla/firefox',
  'microsoft sql server': 'microsoft/sql_server',
  'amazon web services':  'amazon/aws',
  'zoom video':           'zoom/zoom',
};

async function fetchByCVEId(cveId, apiKey) {
  const id  = cveId.toUpperCase();
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`;
  const nvd = await nvdFetch(url, apiKey);
  if (nvd.ok) {
    const cves = (nvd.data.vulnerabilities || []).map(v => v.cve);
    if (cves.length) return { cves, source: 'nvd' };
  }
  const circl = await circlById(id);
  if (circl) return { cves: [circl], source: 'circl' };
  return { cves: [], source: 'none', reason: nvd.reason || 'Not found' };
}

async function fetchByKeyword(keyword, count, apiKey) {
  const kw = keyword.toLowerCase();
  const nvdTerms = NVD_KEYWORD_MAP[kw] || [keyword];
  const log = [];
  const hasKey = !!apiKey;

  for (const term of nvdTerms) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(term)}&resultsPerPage=${count}&sortBy=publishDate&sortOrder=desc`;
    const nvd = await nvdFetch(url, apiKey);
    log.push({ term, ok: nvd.ok, reason: nvd.reason, count: nvd.ok ? (nvd.data.vulnerabilities||[]).length : 0 });
    if (nvd.ok) {
      const cves = (nvd.data.vulnerabilities || []).map(v => v.cve);
      if (cves.length) return { cves, source: 'nvd', hasKey };
    }
    if (nvd.reason && nvd.reason.includes('rate')) break;
  }

  // CIRCL fallback
  const circlPath = CIRCL_VENDOR_MAP[kw];
  log.push({ circl: circlPath || 'no mapping' });
  if (circlPath) {
    const cves = await circlByVendor(circlPath, count);
    log.push({ circlResults: cves.length });
    if (cves.length) return { cves, source: 'circl', hasKey };
  }

  // Always include debug info in the zero-result response
  return { cves: [], source: 'none', reason: '0 results', hasKey, debug: log };
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
    // No caching — fetch fresh every time so we don't cache failures
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
