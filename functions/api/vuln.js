/**
 * Cloudflare Pages Function — /api/vuln
 * Place at: functions/api/vuln.js
 *
 * Environment variables (Cloudflare Pages → Settings → Environment variables):
 *   NVD_API_KEY  — NIST NVD API key (boosts rate limit from 5→50 req/30s)
 *
 * GET /api/vuln?q=<keyword or CVE-ID>&limit=20
 *
 * Pipeline:
 *   Phase 1 → NVD keyword/CVE search
 *   Phase 2 → parallel enrichment: EPSS + CISA KEV + OSV + GitHub Advisories
 *   Returns single merged JSON blob to the browser
 */

export async function onRequestGet(context) {
  const { request, env } = context;
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
  };

  const url   = new URL(request.url);
  const q     = url.searchParams.get('q')?.trim() || '';
  const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '20'), 1), 50);

  if (!q) return resp({ error: 'Missing query param: q' }, 400, cors);

  const NVD_KEY = env.NVD_API_KEY || '';
  const isCVE   = /^CVE-\d{4}-\d+$/i.test(q);

  /* PHASE 1: NVD ---------------------------------------------------------- */
  const nvdUrl = isCVE
    ? `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(q.toUpperCase())}`
    : `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(q)}&resultsPerPage=${limit}&startIndex=0`;

  let nvdJson = null, nvdErr = null;
  try {
    const nvdRes = await fetch(nvdUrl, {
      headers: {
        'Accept': 'application/json',
        ...(NVD_KEY ? { apiKey: NVD_KEY } : {}),
      },
    });
    if (nvdRes.ok) {
      nvdJson = await nvdRes.json();
    } else if (nvdRes.status === 429) {
      nvdErr = 'NVD rate limited — add NVD_API_KEY to Cloudflare env vars';
    } else {
      nvdErr = `NVD HTTP ${nvdRes.status}`;
    }
  } catch (e) {
    nvdErr = `NVD unreachable: ${e.message}`;
  }

  const cves   = (nvdJson?.vulnerabilities || []).map(v => v.cve);
  const cveIds = cves.map(c => c.id);

  if (!cveIds.length) {
    return resp({
      cves: [],
      github: [],
      meta: { total: 0, returned: 0, query: q, kevCount: 0, error: nvdErr },
    }, 200, cors);
  }

  /* PHASE 2: Parallel enrichment ------------------------------------------ */
  const [epssRes, kevRes, osvRes, ghRes] = await Promise.allSettled([
    enrichEPSS(cveIds),
    enrichKEV(cveIds),
    enrichOSV(cveIds),
    enrichGitHub(q, isCVE ? q.toUpperCase() : null),
  ]);

  const epssMap = epssRes.status === 'fulfilled' ? epssRes.value : {};
  const kevSet  = kevRes.status  === 'fulfilled' ? kevRes.value  : new Set();
  const osvMap  = osvRes.status  === 'fulfilled' ? osvRes.value  : {};
  const github  = ghRes.status   === 'fulfilled' ? ghRes.value   : [];

  /* Merge ------------------------------------------------------------------ */
  const enriched = cves.map(cve => ({
    id:           cve.id,
    published:    cve.published,
    lastModified: cve.lastModified,
    description:  cve.descriptions?.find(d => d.lang === 'en')?.value || '',
    cvss:         extractCVSS(cve),
    cwe:          extractCWE(cve),
    references:   (cve.references || []).slice(0, 8).map(r => r.url),
    epss:         epssMap[cve.id] || null,
    kev:          kevSet.has(cve.id),
    osv:          osvMap[cve.id]  || null,
  }));

  return resp({
    cves: enriched,
    github,
    meta: {
      total:    nvdJson?.totalResults || cves.length,
      returned: enriched.length,
      query:    q,
      kevCount: enriched.filter(c => c.kev).length,
      sources: {
        nvd:    true,
        epss:   epssRes.status === 'fulfilled',
        kev:    kevRes.status  === 'fulfilled',
        osv:    osvRes.status  === 'fulfilled',
        github: ghRes.status   === 'fulfilled',
      },
    },
  }, 200, cors);
}

/* ENRICHMENT FUNCTIONS ------------------------------------------------------ */

async function enrichEPSS(cveIds) {
  const url = `https://api.first.org/data/v1/epss?cve=${cveIds.join(',')}&pretty=true`;
  const res  = await fetch(url);
  if (!res.ok) throw new Error(`EPSS ${res.status}`);
  const data = await res.json();
  const map  = {};
  for (const item of (data.data || [])) {
    map[item.cve] = {
      score:      parseFloat(item.epss),
      percentile: parseFloat(item.percentile),
    };
  }
  return map;
}

async function enrichKEV(cveIds) {
  const res = await fetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  );
  if (!res.ok) throw new Error(`KEV ${res.status}`);
  const data   = await res.json();
  const allKev = new Set((data.vulnerabilities || []).map(v => v.cveID));
  return new Set(cveIds.filter(id => allKev.has(id)));
}

async function enrichOSV(cveIds) {
  const res = await fetch('https://api.osv.dev/v1/querybatch', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ queries: cveIds.map(id => ({ cve: id })) }),
  });
  if (!res.ok) throw new Error(`OSV ${res.status}`);
  const data = await res.json();
  const map  = {};
  (data.results || []).forEach((result, i) => {
    const vulns = result.vulns || [];
    if (vulns.length > 0) {
      map[cveIds[i]] = {
        count: vulns.length,
        ids:   vulns.slice(0, 4).map(v => v.id),
      };
    }
  });
  return map;
}

async function enrichGitHub(keyword, cveId) {
  const url = cveId
    ? `https://api.github.com/advisories?cve_id=${encodeURIComponent(cveId)}&per_page=10`
    : `https://api.github.com/advisories?query=${encodeURIComponent(keyword)}&per_page=12`;

  const res = await fetch(url, {
    headers: {
      'Accept':     'application/vnd.github.v3+json',
      'User-Agent': 'VulnIntel-CF/2.0',
    },
  });
  if (!res.ok) throw new Error(`GitHub ${res.status}`);
  const data = await res.json();
  return (Array.isArray(data) ? data : []).map(a => ({
    ghsaId:    a.ghsa_id,
    cveId:     a.cve_id,
    summary:   a.summary,
    severity:  a.severity,
    url:       a.html_url,
    packages:  (a.vulnerabilities || []).slice(0, 2).map(v => ({
      name:      v.package?.name,
      ecosystem: v.package?.ecosystem,
    })),
    published: a.published_at,
  }));
}

/* NVD DATA EXTRACTORS ------------------------------------------------------- */

function extractCVSS(cve) {
  const m = cve.metrics || {};
  for (const key of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const arr = m[key];
    if (arr?.length) {
      const d = arr[0].cvssData || arr[0];
      return {
        version:  d.version || (key.includes('V2') ? '2.0' : '3.x'),
        score:    d.baseScore,
        severity: d.baseSeverity || arr[0].baseSeverity || scoreSeverity(d.baseScore, key),
        vector:   d.vectorString,
      };
    }
  }
  return null;
}

function extractCWE(cve) {
  return (cve.weaknesses || [])
    .flatMap(x => x.description || [])
    .filter(d => d.value !== 'NVD-CWE-noinfo')
    .map(d => d.value)
    .slice(0, 3);
}

function scoreSeverity(score, metricKey) {
  if (!score) return 'NONE';
  if (metricKey.includes('V2')) {
    if (score >= 7) return 'HIGH';
    if (score >= 4) return 'MEDIUM';
    return 'LOW';
  }
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0)  return 'LOW';
  return 'NONE';
}

function resp(body, status, headers) {
  return new Response(JSON.stringify(body), { status, headers });
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
