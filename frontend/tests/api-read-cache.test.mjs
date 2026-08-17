import assert from "node:assert/strict";
import test from "node:test";

const apiURL = new URL("../lib/api.ts", import.meta.url);

test("deduplicates, reload-caches, refreshes and invalidates GET queries", async () => {
  const originalWindow = globalThis.window;
  const originalDocument = globalThis.document;
  const originalFetch = globalThis.fetch;
  const entries = new Map();
  const sessionStorage = {
    get length() { return entries.size; },
    getItem(key) { return entries.get(key) ?? null; },
    key(index) { return [...entries.keys()][index] ?? null; },
    removeItem(key) { entries.delete(key); },
    setItem(key, value) { entries.set(key, String(value)); },
  };
  const calls = new Map();
  globalThis.window = { sessionStorage, addEventListener() {} };
  globalThis.document = { cookie: "" };
  globalThis.fetch = async (path, init = {}) => {
    const key = `${init.method || "GET"} ${path}`;
    calls.set(key, (calls.get(key) || 0) + 1);
    const callNumber = calls.get(key);
    if (path === "/api/v1/projects")
      await new Promise((resolve) => setTimeout(resolve, 20));
    if (path.includes("/managed-tunnels") && callNumber === 1)
      await new Promise((resolve) => setTimeout(resolve, 20));
    const headers = path.includes("/credentials")
      ? { "Cache-Control": "no-store" }
      : {};
    const body = path === "/api/v1/nodes"
      ? { items: [{ id: "node-1" }] }
      : path === "/api/v1/projects"
        ? { items: [{ id: "project-1" }] }
        : path === "/api/v1/users"
          ? { items: [{ id: "user-1", username: "sensitive-user" }] }
        : path.includes("/managed-tunnels")
          ? { items: [{ id: callNumber, clientId: 1 }] }
          : path.includes("/credentials")
            ? { basicUsername: "user", basicPassword: "password", verifyKey: "vkey" }
            : { id: "node-1" };
    return new Response(JSON.stringify(body), { status: 200, headers });
  };

  try {
    const first = await import(`${apiURL.href}?cache-runtime-first`);
    await Promise.all([first.api.projects(), first.api.projects()]);
    assert.equal(calls.get("GET /api/v1/projects"), 1, "concurrent reads must share one request");

    await first.api.nodes();
    await first.api.nodes();
    assert.equal(calls.get("GET /api/v1/nodes"), 1, "same-page reads must use the short cache");

    const reloaded = await import(`${apiURL.href}?cache-runtime-reload`);
    await reloaded.api.nodes();
    assert.equal(calls.get("GET /api/v1/nodes"), 1, "a short reload must reuse session cache");

    await first.api.users();
    await first.api.users();
    assert.equal(calls.get("GET /api/v1/users"), 1, "same-page sensitive reads may use memory cache");
    assert.equal([...entries.keys()].some((key) => key.endsWith("/api/v1/users")), false, "sensitive reads must not enter session storage");
    await reloaded.api.users();
    assert.equal(calls.get("GET /api/v1/users"), 2, "a reload must synchronize sensitive reads again");

    const nodeCacheKey = [...entries.keys()].find((key) => key.endsWith("/api/v1/nodes"));
    const expiredNodeCache = JSON.parse(entries.get(nodeCacheKey));
    entries.set(nodeCacheKey, JSON.stringify({ ...expiredNodeCache, storedAt: Date.now() - 10_001 }));
    await reloaded.api.nodes();
    assert.equal(calls.get("GET /api/v1/nodes"), 2, "an expired reload cache must synchronize again");

    const olderTunnelRead = first.api.managedTunnels("node-1");
    await new Promise((resolve) => setTimeout(resolve, 5));
    const refreshedTunnels = await first.api.managedTunnels("node-1", true);
    await olderTunnelRead;
    const cachedTunnels = await first.api.managedTunnels("node-1");
    assert.equal(calls.get("GET /api/v1/nodes/node-1/managed-tunnels"), 2, "manual refresh must bypass cache");
    assert.equal(refreshedTunnels[0].id, 2);
    assert.equal(cachedTunnels[0].id, 2, "an older concurrent response must not replace fresh data");
    const repeatedFresh = await Promise.all([
      first.api.managedTunnels("node-1", true),
      first.api.managedTunnels("node-1", true),
    ]);
    assert.equal(calls.get("GET /api/v1/nodes/node-1/managed-tunnels"), 2, "rapid manual refreshes must reuse the latest result");
    assert.equal(repeatedFresh[0][0].id, 2);
    assert.equal(repeatedFresh[1][0].id, 2);

    await first.api.nodeClientCredentials("node-1", 1);
    await first.api.nodeClientCredentials("node-1", 1);
    assert.equal(calls.get("GET /api/v1/nodes/node-1/clients/1/credentials"), 2, "no-store responses must never persist");

    await first.api.me();
    await first.api.me();
    assert.equal(calls.get("GET /api/v1/auth/me"), 2, "authentication must be revalidated on every page load");

    await first.api.createNode({ name: "updated" });
    await first.api.nodes();
    assert.equal(calls.get("GET /api/v1/nodes"), 3, "a successful mutation must invalidate reads");
  } finally {
    globalThis.window = originalWindow;
    globalThis.document = originalDocument;
    globalThis.fetch = originalFetch;
  }
});
