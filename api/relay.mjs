const BLOCKED_HEADERS = new Set([
  "host",
  "content-length",
  "connection",
  "transfer-encoding",
  "upgrade",
  "proxy-authorization",
  "keep-alive",
  "te",
  "trailer"
]);

function isPrivateOrLocalHost(hostname) {
  const h = String(hostname || "").toLowerCase();
  return (
    h === "localhost" ||
    h.endsWith(".local") ||
    h === "0.0.0.0" ||
    h === "::1" ||
    h === "[::1]" ||
    /^127\./.test(h) ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^169\.254\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(h)
  );
}

async function drainBody(response) {
  if (!response.body) return 0;
  const reader = response.body.getReader();
  let bytesConsumed = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) bytesConsumed += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return bytesConsumed;
}

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const relayToken = process.env.RELAY_TOKEN || "";
    const requestUrl = new URL(request.url);
    const suppliedToken =
      requestUrl.searchParams.get("token") ||
      request.headers.get("x-relay-token") ||
      "";

    if (!relayToken || suppliedToken !== relayToken) {
      return new Response("Unauthorized", { status: 401 });
    }

    let payload;
    try {
      payload = await request.json();
    } catch {
      return new Response("Invalid JSON", { status: 400 });
    }

    let targetUrl;
    try {
      targetUrl = new URL(String(payload?.url || ""));
    } catch {
      return new Response("Invalid target URL", { status: 400 });
    }

    if (targetUrl.protocol !== "https:" && targetUrl.protocol !== "http:") {
      return new Response("Unsupported protocol", { status: 400 });
    }

    if (isPrivateOrLocalHost(targetUrl.hostname)) {
      return new Response("Target host blocked", { status: 403 });
    }

    const method = String(payload?.method || "GET").toUpperCase();
    if (!["GET", "HEAD", "POST"].includes(method)) {
      return new Response("Unsupported method", { status: 400 });
    }

    const headers = new Headers();
    if (payload?.headers && typeof payload.headers === "object" && !Array.isArray(payload.headers)) {
      for (const [name, value] of Object.entries(payload.headers)) {
        if (!BLOCKED_HEADERS.has(name.toLowerCase()) && value !== undefined && value !== null) {
          headers.set(name, String(value));
        }
      }
    }

    const body =
      method === "GET" || method === "HEAD" || payload?.body === null || payload?.body === undefined
        ? undefined
        : String(payload.body);

    try {
      const upstream = await fetch(targetUrl.toString(), {
        method,
        headers,
        body,
        redirect: "follow",
        signal: AbortSignal.timeout(40000)
      });
      const bytesConsumed = method === "HEAD" ? 0 : await drainBody(upstream);
      const responseHeaders = new Headers({
        "Cache-Control": "no-store",
        "X-Relay-Body-Bytes-Consumed": String(bytesConsumed)
      });

      const status = upstream.status;
      const responseBody = [204, 205, 304].includes(status) ? null : undefined;

      return new Response(responseBody, {
        status,
        headers: responseHeaders
      });
    } catch {
      return new Response("Relay request failed", {
        status: 502,
        headers: { "Cache-Control": "no-store" }
      });
    }
  }
};
