/**
 * Cloudflare Pages Function — /api/vuln
 * Place this file at: functions/api/vuln.js
 *
 * Required environment variable (set in Cloudflare Pages → Settings → Environment variables):
 *   NVD_API_KEY  — your NIST NVD API key
 *
 * Usage from the frontend:
 *   GET /api/vuln?url=<url-encoded NVD API URL>
 */

export async function onRequestGet(context) {
  const { request, env } = context;

  /* ── CORS headers so the browser page can call this freely ── */
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  /* ── Extract the target NVD URL from the query string ── */
  const reqUrl = new URL(request.url);
  const targetUrl = reqUrl.searchParams.get('url');

  if (!targetUrl) {
    return new Response(
      JSON.stringify({ error: 'Missing required query param: url' }),
      { status: 400, headers: corsHeaders }
    );
  }

  /* ── Only allow calls to the official NVD endpoint ── */
  if (!targetUrl.startsWith('https://services.nvd.nist.gov/')) {
    return new Response(
      JSON.stringify({ error: 'Only NVD endpoints are permitted.' }),
      { status: 403, headers: corsHeaders }
    );
  }

  /* ── Attach the API key from the environment variable ── */
  const apiKey = env.NVD_API_KEY || '';
  const nvdHeaders = {
    'Accept': 'application/json',
    ...(apiKey ? { 'apiKey': apiKey } : {}),
  };

  /* ── Forward the request to NVD ── */
  try {
    const nvdRes = await fetch(targetUrl, {
      headers: nvdHeaders,
      cf: { cacheTtl: 300, cacheEverything: true }, // cache for 5 min at the edge
    });

    if (!nvdRes.ok) {
      return new Response(
        JSON.stringify({ error: `NVD returned HTTP ${nvdRes.status}` }),
        { status: nvdRes.status, headers: corsHeaders }
      );
    }

    const data = await nvdRes.json();
    return new Response(JSON.stringify(data), { status: 200, headers: corsHeaders });

  } catch (err) {
    return new Response(
      JSON.stringify({ error: `Proxy fetch failed: ${err.message}` }),
      { status: 502, headers: corsHeaders }
    );
  }
}

/* Handle OPTIONS preflight */
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
