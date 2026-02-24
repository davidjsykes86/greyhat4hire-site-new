/**
 * Cloudflare Pages Function — /api/vuln
 * Place at: functions/api/vuln.js
 *
 * This function ONLY proxies CISA KEV — the one API that blocks browser CORS.
 * NVD, EPSS, OSV, and GitHub are all called directly from the browser.
 *
 * GET /api/vuln?action=kev
 * Returns the full CISA KEV catalogue as JSON.
 */

export async function onRequestGet(context) {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  try {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { headers: { 'User-Agent': 'VulnIntel-Proxy/1.0' } }
    );

    if (!res.ok) {
      return new Response(JSON.stringify({ error: `CISA KEV HTTP ${res.status}` }), { status: res.status, headers: cors });
    }

    const data = await res.json();
    // Return just the CVE ID set for efficiency
    const ids = (data.vulnerabilities || []).map(v => v.cveID);
    return new Response(JSON.stringify({ ids, count: ids.length }), {
      status: 200,
      headers: { ...cors, 'Cache-Control': 'public, max-age=3600' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: cors });
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
