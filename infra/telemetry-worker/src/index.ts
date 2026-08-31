/**
 * ATR Telemetry Worker (Cloudflare Workers)
 *
 * Receives per-consumer telemetry POSTs and stores them in a KV
 * namespace for the daily aggregator to pick up. See
 * docs/telemetry-spec.md for the request/response contract.
 *
 * Endpoints:
 *   POST /v1/report
 *   GET  /v1/health  — returns worker version + UTC timestamp
 *
 * Security:
 *   - X-ATR-Consumer header must be a registered consumer id (env
 *     secret CONSUMER_KEY_<id> exists)
 *   - X-ATR-Signature header must be HMAC-SHA256 hex of the request
 *     body using the consumer's pre-shared key
 *   - Rate limit: 1 successful report per consumer per hour (KV-backed)
 *
 * Storage:
 *   - Reports keyed `<consumer>/<YYYY-MM-DD>/<report_id>` in the
 *     REPORTS KV namespace
 *   - report_id is sha256(body)[:16] for deduplication
 *
 * What this worker explicitly does NOT do:
 *   - Inspect raw event payloads (rejected at validation if present)
 *   - Forward to any third party
 *   - Log to anywhere outside Cloudflare's own request log
 */

export interface Env {
  REPORTS: KVNamespace;
  ATR_VERSION: string;
  WORKER_VERSION: string;
  // Per-consumer HMAC keys live in encrypted secrets:
  // CONSUMER_KEY_microsoft_agt, CONSUMER_KEY_cisco_ai_defense, etc.
  [key: `CONSUMER_KEY_${string}`]: string | undefined;
}

interface ReportRuleEntry {
  rule_id: string;
  fire_count: number;
  fp_dismissed_count: number;
  fp_confirmed_count: number;
  action_distribution?: Record<string, number>;
  confidence_buckets?: Record<string, number>;
}

interface ReportBody {
  consumer_id: string;
  consumer_version?: string;
  report_period_start: string;
  report_period_end: string;
  atr_version: string;
  deployment_count: number;
  rules: ReportRuleEntry[];
}

const FORBIDDEN_FIELDS = new Set([
  "user_id",
  "session_id",
  "ip_address",
  "user_email",
  "raw_event",
  "raw_prompt",
  "raw_response",
  "deployment_id",
  "customer_id",
]);

function json(
  status: number,
  body: unknown,
  extraHeaders: HeadersInit = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "x-atr-worker-version": "v0.1",
      ...extraHeaders,
    },
  });
}

async function hmacHex(key: string, body: string): Promise<string> {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(body));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(body: string): Promise<string> {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(body));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function validateReportShape(b: unknown): b is ReportBody {
  if (!b || typeof b !== "object") return false;
  const r = b as Partial<ReportBody>;
  if (typeof r.consumer_id !== "string") return false;
  if (typeof r.report_period_start !== "string") return false;
  if (typeof r.report_period_end !== "string") return false;
  if (typeof r.atr_version !== "string") return false;
  if (typeof r.deployment_count !== "number" || r.deployment_count < 0)
    return false;
  if (!Array.isArray(r.rules)) return false;
  for (const rule of r.rules) {
    if (!rule || typeof rule !== "object") return false;
    const k = rule as Partial<ReportRuleEntry>;
    if (typeof k.rule_id !== "string") return false;
    if (!/^ATR-\d{4}-\d{5}$/.test(k.rule_id)) return false;
    if (typeof k.fire_count !== "number") return false;
    if (typeof k.fp_dismissed_count !== "number") return false;
    if (typeof k.fp_confirmed_count !== "number") return false;
  }
  return true;
}

function containsForbiddenField(obj: unknown): string | null {
  if (!obj || typeof obj !== "object") return null;
  for (const key of Object.keys(obj)) {
    if (FORBIDDEN_FIELDS.has(key)) return key;
    const sub = (obj as Record<string, unknown>)[key];
    if (sub && typeof sub === "object") {
      const inner = containsForbiddenField(sub);
      if (inner) return `${key}.${inner}`;
    }
  }
  return null;
}

async function checkRateLimit(
  reports: KVNamespace,
  consumerId: string,
): Promise<boolean> {
  const key = `rate/${consumerId}`;
  const seen = await reports.get(key);
  if (seen) return false;
  await reports.put(key, "1", { expirationTtl: 3600 }); // 1 hour
  return true;
}

async function handleReport(req: Request, env: Env): Promise<Response> {
  const consumerId = req.headers.get("X-ATR-Consumer");
  if (!consumerId) return json(401, { error: "missing X-ATR-Consumer header" });
  if (!/^[a-z0-9-]{1,64}$/.test(consumerId))
    return json(401, { error: "invalid consumer id format" });

  const sigHeader = req.headers.get("X-ATR-Signature");
  if (!sigHeader || !sigHeader.startsWith("sha256="))
    return json(401, { error: "missing or malformed X-ATR-Signature" });
  const providedSig = sigHeader.slice("sha256=".length);

  // Pre-shared key for this consumer.
  const keyVar =
    `CONSUMER_KEY_${consumerId.replace(/-/g, "_")}` as `CONSUMER_KEY_${string}`;
  const consumerKey = env[keyVar];
  if (!consumerKey) return json(401, { error: "unknown consumer id" });

  const body = await req.text();
  if (body.length > 5 * 1024 * 1024)
    return json(413, { error: "request body too large (max 5 MiB)" });

  const expectedSig = await hmacHex(consumerKey, body);
  if (!timingSafeEqualHex(providedSig, expectedSig))
    return json(401, { error: "signature mismatch" });

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return json(400, { error: "body is not valid JSON" });
  }
  if (!validateReportShape(parsed))
    return json(400, { error: "report does not match expected schema" });
  const report = parsed as ReportBody;

  if (report.consumer_id !== consumerId)
    return json(400, {
      error: "consumer_id in body does not match X-ATR-Consumer header",
    });

  const forbidden = containsForbiddenField(parsed);
  if (forbidden)
    return json(400, {
      error: `report contains forbidden PII field: ${forbidden}`,
      note: "see docs/telemetry-spec.md for the allowed schema",
    });

  const allowed = await checkRateLimit(env.REPORTS, consumerId);
  if (!allowed) return json(429, { error: "rate limit: 1 report per hour" });

  const reportId = (await sha256Hex(body)).slice(0, 16);
  const day = report.report_period_end.slice(0, 10);
  const key = `${consumerId}/${day}/${reportId}`;
  await env.REPORTS.put(key, body, {
    // Keep reports for 60 days; aggregator runs daily so 60 covers the
    // 30-day window with margin for late catch-up.
    expirationTtl: 60 * 24 * 3600,
    metadata: {
      received_at: new Date().toISOString(),
      consumer_version: report.consumer_version,
      atr_version: report.atr_version,
      rule_count: report.rules.length,
    },
  });

  return json(202, {
    accepted: true,
    consumer_id: consumerId,
    report_id: `rep_${day.replace(/-/g, "_")}_${consumerId.replace(/-/g, "_")}_${reportId}`,
    ingest_lag_ms: 0,
    auto_actions: [], // Computed offline by scripts/aggregate-telemetry.ts
  });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "GET" && url.pathname === "/v1/health") {
      return json(200, {
        ok: true,
        worker_version: env.WORKER_VERSION,
        atr_version: env.ATR_VERSION,
        utc: new Date().toISOString(),
      });
    }
    if (req.method === "POST" && url.pathname === "/v1/report") {
      try {
        return await handleReport(req, env);
      } catch (e) {
        return json(500, {
          error: "internal worker error",
          detail: e instanceof Error ? e.message : String(e),
        });
      }
    }
    return json(404, { error: "not found" });
  },
} satisfies ExportedHandler<Env>;
