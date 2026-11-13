export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const expectedToken = process.env.RELAY_TOKEN || "";
    const reqUrl = new URL(request.url);
    const providedToken = reqUrl.searchParams.get("token") || request.headers.get("x-relay-token") || "";
    if (!expectedToken || providedToken !== expectedToken) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json; charset=UTF-8" }
      });
    }

    let payload;
    try {
      payload = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), {
        status: 400,
        headers: { "content-type": "application/json; charset=UTF-8" }
      });
    }

    let targetUrl;
    try {
      targetUrl = new URL(String(payload?.url || ""));
      if (targetUrl.protocol !== "https:" && targetUrl.protocol !== "http:") {
        throw new Error("Invalid protocol");
      }
    } catch {
      return new Response(JSON.stringify({ error: "Invalid target url" }), {
        status: 400,
        headers: { "content-type": "application/json; charset=UTF-8" }
      });
    }

    const method = String(payload?.method || "GET").toUpperCase();
    const forwardHeaders = {};
    if (payload?.headers && typeof payload.headers === "object") {
      for (const [key, value] of Object.entries(payload.headers)) {
        const lower = String(key).toLowerCase();
        if (lower === "host" || lower === "content-length" || lower === "connection") continue;
        forwardHeaders[key] = String(value);
      }
    }

    const init = {
      method,
      headers: forwardHeaders,
      redirect: "follow",
      signal: AbortSignal.timeout(25000)
    };
    if (method !== "GET" && method !== "HEAD" && payload?.body !== null && payload?.body !== undefined) {
      init.body = String(payload.body);
    }

    try {
      const upstream = await fetch(targetUrl.toString(), init);
      const respHeaders = new Headers();
      for (const [key, value] of upstream.headers.entries()) {
        const lower = key.toLowerCase();
        if (lower === "content-encoding" || lower === "content-length" || lower === "transfer-encoding" || lower === "connection") {
          continue;
        }
        respHeaders.set(key, value);
      }
      respHeaders.set("x-relay-final-url", upstream.url || targetUrl.toString());
      const body = method === "HEAD" || upstream.status === 204 || upstream.status === 304 ? null : upstream.body;
      return new Response(body, {
        status: upstream.status,
        headers: respHeaders
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: String(error?.message || error) }), {
        status: 502,
        headers: { "content-type": "application/json; charset=UTF-8" }
      });
    }
  }
};
