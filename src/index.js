/**
 * Cloudflare Worker entrypoint (ES module syntax).
 *
 * Static files in `public/` are served through the `ASSETS` binding
 * (configured in wrangler.jsonc). Because `run_worker_first` is enabled,
 * this Worker runs for every request, letting us attach security headers to
 * all responses — including the custom `404.html` served by
 * `not_found_handling: "404-page"`.
 */

const SECURITY_HEADERS = {
  'X-XSS-Protection': '1; mode=block',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'unsafe-url',
  'Feature-Policy': 'none',
};

export default {
  async fetch(request, env) {
    const assetResponse = await env.ASSETS.fetch(request);

    const response = new Response(assetResponse.body, assetResponse);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      response.headers.set(name, value);
    }
    return response;
  },
};
