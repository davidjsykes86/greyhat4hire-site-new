const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';
const ALLOWED_MODEL  = 'claude-sonnet-4-6';
const DAILY_LIMIT    = 5;   // requests per IP per day — change if you want

export async function onRequestPost(context) {
  const { request, env } = context;

  // CORS headers — locked to production domain
  const corsHeaders = {
    'Access-Control-Allow-Origin': 'https://greyhat4hire.com',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  const jsonError = (msg, status = 400) =>
    new Response(JSON.stringify({ error: msg }), {
      status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  // ── Rate limiting (requires KV binding named RATE_LIMIT_KV) ──────────────
  if (env.RATE_LIMIT_KV) {
    const ip  = request.headers.get('CF-Connecting-IP') || 'unknown';
    const day = new Date().toISOString().slice(0, 10);   // "2025-06-01"
    const key = `rl:${ip}:${day}`;
    const raw = await env.RATE_LIMIT_KV.get(key);
    const hits = raw ? parseInt(raw, 10) : 0;
    if (hits >= DAILY_LIMIT) return jsonError('Daily limit reached. Try again tomorrow.', 429);
    await env.RATE_LIMIT_KV.put(key, String(hits + 1), { expirationTtl: 90000 });
  }

  // ── Parse incoming request body ──────────────────────────────────────────
  let body;
  try { body = await request.json(); }
  catch { return jsonError('Invalid JSON body'); }

  // Force the model — client cannot override this
  body.model = ALLOWED_MODEL;

  // ── Forward to Anthropic ─────────────────────────────────────────────────
  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) return jsonError('Server misconfiguration: missing API key', 500);

  const upstream = await fetch(ANTHROPIC_API, {
    method: 'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-beta':    'interleaved-thinking-2025-05-14',
    },
    body: JSON.stringify(body),
  });

  // Stream the response straight back to the browser
  return new Response(upstream.body, {
    status:  upstream.status,
    headers: {
      ...corsHeaders,
      'Content-Type': upstream.headers.get('Content-Type') || 'application/json',
    },
  });
}

// Handle preflight OPTIONS
export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin':  'https://greyhat4hire.com',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
