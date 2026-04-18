export default {
  async fetch(request, env) {
    const upgrade = request.headers.get("Upgrade");
    if (!upgrade || upgrade.toLowerCase() !== "websocket") {
      return new Response("whispera cdn worker", { status: 200 });
    }

    const target = env.WHISPERA_UPSTREAM;
    if (!target) {
      return new Response("WHISPERA_UPSTREAM not configured", { status: 500 });
    }

    const url = new URL(request.url);
    const upstreamURL = `${target}${url.pathname}${url.search}`;

    const fwdHeaders = new Headers(request.headers);
    fwdHeaders.set("Host", new URL(target).host);
    fwdHeaders.set("X-Forwarded-For", request.headers.get("CF-Connecting-IP") || "");
    fwdHeaders.set("X-Forwarded-Proto", "https");

    const expected = env.WHISPERA_ACCESS_TOKEN;
    if (expected) {
      const given = request.headers.get("Authorization") || url.searchParams.get("t");
      if (given !== `Bearer ${expected}` && given !== expected) {
        return new Response("unauthorized", { status: 401 });
      }
    }

    return fetch(upstreamURL, {
      method: request.method,
      headers: fwdHeaders,
      body: request.body,
    });
  },
};
