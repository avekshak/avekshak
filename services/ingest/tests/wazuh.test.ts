import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "http";

// Fixture hits matching Wazuh _search response shape
const FIXTURE_HITS = [
  {
    _source: {
      timestamp: "2026-11-10T02:00:00.000Z",
      agent: { name: "web-01", ip: "10.0.0.5" },
      rule: { description: "SSH brute force", level: 10, groups: ["authentication_failed", "pam"] },
      data: { srcip: "1.2.3.4", srcuser: "admin" },
    },
  },
  {
    _source: {
      timestamp: "2026-11-10T02:01:00.000Z",
      agent: { name: "db-01", ip: "10.0.0.6" },
      rule: { description: "Successful login", level: 3, groups: ["authentication_success"] },
      data: { srcip: "10.0.1.1", srcuser: "kunal" },
    },
  },
  // malformed — should be skipped
  { _source: null },
];

let server: Server;
let serverUrl: string;
const received: unknown[] = [];

beforeAll(async () => {
  // Stub Wazuh/Elastic search endpoint
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push(JSON.parse(body || "{}"));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ hits: { hits: FIXTURE_HITS } }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as { port: number };
  serverUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  server.close();
});

describe("Wazuh connector poll", () => {
  it("fetches hits and normalizes them correctly", async () => {
    const auth = Buffer.from("admin:admin").toString("base64");
    const res = await fetch(`${serverUrl}/wazuh-alerts-*/_search`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${auth}`,
      },
      body: JSON.stringify({ query: { range: { timestamp: { gt: "2026-01-01", lte: new Date().toISOString() } } }, size: 500 }),
    });

    expect(res.ok).toBe(true);
    const json = (await res.json()) as { hits: { hits: unknown[] } };
    expect(json.hits.hits).toHaveLength(3);
  });

  it("normalizes valid hits and skips malformed ones", async () => {
    const { normalizeWazuh } = await import("../src/normalize/wazuh.js");

    const results = FIXTURE_HITS.map(normalizeWazuh).filter(Boolean);
    expect(results).toHaveLength(2);

    const [first, second] = results;
    expect(first!.source).toBe("wazuh");
    expect(first!.action).toBe("login_failed");
    expect(first!.actor.ip).toBe("1.2.3.4");
    expect(first!.actor.user).toBe("admin");

    expect(second!.action).toBe("login_success");
    expect(second!.actor.user).toBe("kunal");
  });

  it("stub server received a well-formed query body", () => {
    expect(received.length).toBeGreaterThan(0);
    const body = received[0] as { query: { range: { timestamp: unknown } }; size: number };
    expect(body.query.range.timestamp).toBeDefined();
    expect(body.size).toBe(500);
  });
});
