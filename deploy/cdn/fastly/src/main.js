/// <reference types="@fastly/js-compute" />
import { env } from "fastly:env";

addEventListener("fetch", (event) => event.respondWith(handler(event)));

async function handler(event) {
  const request = event.request;
  const upgrade = request.headers.get("Upgrade");
  if (!upgrade || upgrade.toLowerCase() !== "websocket") {
    return new Response("whispera cdn worker", { status: 200 });
  }

  const target = env("WHISPERA_UPSTREAM");
  if (!target) {
    return new Response("WHISPERA_UPSTREAM not configured", { status: 500 });
  }

  const url = new URL(request.url);
  const expected = env("WHISPERA_ACCESS_TOKEN");
  if (expected) {
    const given = request.headers.get("Authorization") || url.searchParams.get("t");
    if (given !== `Bearer ${expected}` && given !== expected) {
      return new Response("unauthorized", { status: 401 });
    }
  }

  const upstreamURL = `${target}${url.pathname}${url.search}`;
  const fwdHeaders = new Headers(request.headers);
  fwdHeaders.set("Host", new URL(target).host);
  fwdHeaders.set("X-Forwarded-For", request.headers.get("Fastly-Client-IP") || "");
  fwdHeaders.set("X-Forwarded-Proto", "https");

  return fetch(upstreamURL, {
    method: request.method,
    headers: fwdHeaders,
    body: request.body,
    backend: "origin",
  });
}
