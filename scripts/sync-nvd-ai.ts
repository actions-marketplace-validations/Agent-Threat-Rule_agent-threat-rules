#!/usr/bin/env npx tsx
/**
 * sync-nvd-ai.ts
 *
 * Pulls CVE entries from the National Vulnerability Database (NVD) JSON 2.0
 * API filtered for the AI / agent / LLM / MCP ecosystem and emits ATR rule
 * proposals at proposals/nvd/<CVE-ID>.proposal.yaml.
 *
 * Why NVD when we already have CISA KEV and GHSA?
 *   - NVD covers every MITRE-assigned CVE, including ones that never got
 *     a GHSA entry (older non-GitHub-hosted projects, vendor-only CVEs).
 *   - Lower signal-to-noise than KEV (KEV is curated to exploited-in-wild)
 *     so the AI-vendor allow/deny list does most of the work.
 *
 * Filter strategy (deny-list since NVD is broader than KEV):
 *   1. Query by AI/LLM/agent keyword to bound the result set.
 *   2. For each hit, walk descriptions + CPE matches + reference URLs.
 *   3. Reject if a Microsoft / Google / NVIDIA / Amazon / Meta CPE
 *      appears AND no AI product (Semantic Kernel, Vertex AI, NeMo,
 *      SageMaker, PurpleLlama, etc.) is in the description or CPE.
 *   4. Accept if any AI_VENDORS match (BerriAI, vLLM, LangChain, ...).
 *   5. Accept if any AI_DESC_RX hit (prompt injection, MCP, RAG, ...).
 *
 * Detection-readiness triage (same shape as sync-ghsa.ts):
 *   - true if any NVD reference URL points at exploit-db.com / poc / cve.org
 *     advisory pages OR the description contains payload/PoC markers.
 *
 * Auth & rate limiting:
 *   - NVD allows 5 req / 30 sec unauthenticated, 50 req / 30 sec with an
 *     API key from `NVD_API_KEY`. Header is `apiKey`.
 *   - On 429 we backoff exponentially up to 3 retries, then exit 2.
 *
 * Idempotency:
 *   - Skip if CVE is already covered in rules/ or in any proposals/* dir.
 *
 * Usage:
 *   npx tsx scripts/sync-nvd-ai.ts                     # dry-run, last 90 days
 *   npx tsx scripts/sync-nvd-ai.ts --write             # write proposals
 *   npx tsx scripts/sync-nvd-ai.ts --since 2026-04-01  # custom start date
 *   npx tsx scripts/sync-nvd-ai.ts --cve CVE-2026-12345 # single CVE
 *   npx tsx scripts/sync-nvd-ai.ts --limit 100         # cap output
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 partial (rate-limited; recoverable on next run)
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RULES_DIR = resolve(REPO_ROOT, "rules");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "nvd");

const NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const VERBOSE = flag("--verbose");
const SINCE = opt("--since"); // YYYY-MM-DD
const CVE_FILTER = opt("--cve");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;

const API_KEY = process.env.NVD_API_KEY;

// --- AI relevance heuristics ----------------------------------------------

// Vendors / products that are unambiguously AI ecosystem. Lowercased.
const AI_VENDORS = new Set(
  [
    "berriai",
    "vllm",
    "openai",
    "anthropic",
    "langchain",
    "langchain-ai",
    "llamaindex",
    "pinecone",
    "weaviate",
    "chromadb",
    "chroma",
    "milvus",
    "huggingface",
    "hugging face",
    "transformers",
    "mistral",
    "mistral ai",
    "cohere",
    "fireworks",
    "replicate",
    "together",
    "ollama",
    "llama-cpp",
    "llama_cpp",
    "langgraph",
    "crewai",
    "autogen",
    "semantic-kernel",
    "semantic_kernel",
    "langflow",
    "flowise",
    "agentops",
    "traceloop",
    "openinference",
    "lakera",
    "garak",
    "litellm",
    "haystack",
    "mlflow",
    "ray",
    "gradio",
    "dspy",
    "pyautogen",
    "guardrails",
    "nemoguardrails",
    "promptfoo",
    "pyrit",
    "mcp",
    "fastmcp",
    "modelcontextprotocol",
    "qdrant",
    "embedchain",
    "instructor",
  ].map((s) => s.toLowerCase()),
);

// "Big tech" vendors. Match here triggers the deny rule UNLESS an AI product
// term also appears.
const BIG_TECH_VENDORS = new Set(
  [
    "microsoft",
    "google",
    "nvidia",
    "amazon",
    "amazon_web_services",
    "aws",
    "meta",
    "facebook",
    "apple",
    "ibm",
    "oracle",
    "alibaba",
  ].map((s) => s.toLowerCase()),
);

// AI product names that "rescue" a big-tech CVE so it still counts.
const AI_PRODUCT_RX =
  /(?:^|\W)(?:semantic[- ]kernel|vertex[- ]ai|nemo|nemo[- ]guardrails|sagemaker|bedrock|purplellama|prompt[- ]flow|copilot|azure[- ]openai|azure[- ]ai|llamaindex|langchain|llama|llava|huggingface|transformers|gemini|claude|gpt|chatgpt|vllm|mcp\b|model[- ]context[- ]protocol|llm|generative[- ]ai|agent[- ]framework)(?:\W|$)/i;

const AI_DESC_RX =
  /\b(?:llm|large language model|generative ai|gen[- ]?ai|ai[- ]agent|autonomous agent|prompt injection|tool poisoning|model context protocol|\bmcp\b|vector store|vector embedding|embedding model|skill\.md|claude\.md|cursor[- ]rules?|copilot|chatgpt|gpt-?[0-9]|rag|retrieval[- ]augmented|agentic|tool[- ]use|jailbreak)\b/i;

const NVD_KEYWORDS = [
  "langchain",
  "llamaindex",
  "vllm",
  "mcp",
  "llm",
  "model context protocol",
  "agent framework",
  "prompt injection",
  "tool poisoning",
  "openai",
  "anthropic",
  "huggingface",
  "litellm",
  "ollama",
  "autogen",
  "crewai",
  "semantic kernel",
];

interface NvdReference {
  url: string;
  source?: string;
  tags?: string[];
}

interface NvdWeakness {
  source?: string;
  type?: string;
  description?: { lang?: string; value?: string }[];
}

interface NvdDescription {
  lang?: string;
  value?: string;
}

interface NvdCpeMatch {
  vulnerable?: boolean;
  criteria?: string;
  matchCriteriaId?: string;
}

interface NvdCpeNode {
  operator?: string;
  negate?: boolean;
  cpeMatch?: NvdCpeMatch[];
}

interface NvdConfiguration {
  nodes?: NvdCpeNode[];
}

interface NvdMetricCvssV3 {
  cvssData?: {
    vectorString?: string;
    baseScore?: number;
    baseSeverity?: string;
  };
  exploitabilityScore?: number;
  impactScore?: number;
}

interface NvdMetrics {
  cvssMetricV31?: NvdMetricCvssV3[];
  cvssMetricV30?: NvdMetricCvssV3[];
}

interface NvdCveItem {
  id: string;
  sourceIdentifier?: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: NvdDescription[];
  metrics?: NvdMetrics;
  weaknesses?: NvdWeakness[];
  configurations?: NvdConfiguration[];
  references?: NvdReference[];
}

interface NvdVulnEnvelope {
  cve: NvdCveItem;
}

interface NvdResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: NvdVulnEnvelope[];
}

// --- existing CVE index ---------------------------------------------------

function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    let st;
    try {
      st = statSync(f);
    } catch {
      continue;
    }
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && (e.endsWith(".yaml") || e.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

function buildCveIndex(): Set<string> {
  const ix = new Set<string>();
  for (const dir of [RULES_DIR, PROPOSALS_BASE]) {
    for (const f of walkYaml(dir)) {
      let raw: string;
      try {
        raw = readFileSync(f, "utf-8");
      } catch {
        continue;
      }
      let doc: unknown;
      try {
        doc = yaml.load(raw);
      } catch {
        continue;
      }
      const refs = (doc as { references?: { cve?: string[] } })?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") ix.add(c);
    }
  }
  return ix;
}

// --- CWE -> ATR category mapping ------------------------------------------

const CWE_TO_CATEGORY: Record<string, string> = {
  "CWE-77": "prompt-injection",
  "CWE-78": "tool-poisoning",
  "CWE-79": "context-exfiltration",
  "CWE-89": "data-poisoning",
  "CWE-94": "prompt-injection",
  "CWE-95": "prompt-injection",
  "CWE-20": "prompt-injection",
  "CWE-22": "tool-poisoning",
  "CWE-200": "context-exfiltration",
  "CWE-269": "privilege-escalation",
  "CWE-284": "privilege-escalation",
  "CWE-287": "privilege-escalation",
  "CWE-352": "agent-manipulation",
  "CWE-502": "tool-poisoning",
  "CWE-601": "tool-poisoning",
  "CWE-611": "context-exfiltration",
  "CWE-639": "privilege-escalation",
  "CWE-732": "privilege-escalation",
  "CWE-862": "privilege-escalation",
  "CWE-863": "privilege-escalation",
  "CWE-918": "context-exfiltration",
  "CWE-1336": "prompt-injection",
};

function guessCategory(cwes: string[]): string {
  for (const c of cwes) {
    if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  }
  return "prompt-injection";
}

// --- severity derivation --------------------------------------------------

function severityFromScore(score: number | undefined): {
  severity: string;
  isHigh: boolean;
} {
  if (score === undefined || score === null)
    return { severity: "medium", isHigh: false };
  if (score >= 9.0) return { severity: "critical", isHigh: true };
  if (score >= 7.0) return { severity: "high", isHigh: true };
  if (score >= 4.0) return { severity: "medium", isHigh: false };
  return { severity: "low", isHigh: false };
}

// --- AI relevance check ---------------------------------------------------

function extractCpeStrings(item: NvdCveItem): string[] {
  const out: string[] = [];
  for (const cfg of item.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (m.criteria) out.push(m.criteria);
      }
    }
  }
  return out;
}

function extractCpeVendorsProducts(cpes: string[]): {
  vendors: Set<string>;
  products: Set<string>;
} {
  const vendors = new Set<string>();
  const products = new Set<string>();
  for (const cpe of cpes) {
    // cpe:2.3:a:vendor:product:version:...
    const parts = cpe.split(":");
    if (parts.length >= 5) {
      vendors.add(parts[3].toLowerCase());
      products.add(parts[4].toLowerCase());
    }
  }
  return { vendors, products };
}

function isAIRelevant(item: NvdCveItem): { match: boolean; reason: string } {
  const desc =
    (item.descriptions ?? [])
      .find((d) => d.lang === "en")
      ?.value?.toLowerCase() ?? "";
  const cpes = extractCpeStrings(item);
  const { vendors, products } = extractCpeVendorsProducts(cpes);
  const cpeText = cpes.join(" ").toLowerCase();

  // 1. AI vendor allow-list win
  for (const v of vendors) {
    if (AI_VENDORS.has(v)) return { match: true, reason: `cpe vendor=${v}` };
  }
  for (const p of products) {
    if (AI_VENDORS.has(p)) return { match: true, reason: `cpe product=${p}` };
  }

  // 2. AI product regex on cpe text or description
  if (AI_PRODUCT_RX.test(cpeText))
    return { match: true, reason: "AI_PRODUCT_RX hit in cpe" };
  if (AI_PRODUCT_RX.test(desc))
    return { match: true, reason: "AI_PRODUCT_RX hit in description" };

  // 3. Big-tech deny gate: if vendor is big-tech and nothing AI-specific in
  // description, reject. We've already failed the rescue checks above.
  const hasBigTech = [...vendors].some((v) => BIG_TECH_VENDORS.has(v));
  if (hasBigTech) {
    return { match: false, reason: "big-tech vendor without AI product term" };
  }

  // 4. AI keywords in description as last resort
  if (AI_DESC_RX.test(desc))
    return { match: true, reason: "AI_DESC_RX hit in description" };

  return { match: false, reason: "no AI signal" };
}

// --- detection readiness triage -------------------------------------------

const PAYLOAD_HEURISTICS_RX = /(payload|poc|proof of concept|reproducer|exploit|jailbreak)/i;

function isDetectionReady(item: NvdCveItem): {
  ready: boolean;
  pocUrl: string | null;
  reason: string;
} {
  const desc =
    (item.descriptions ?? []).find((d) => d.lang === "en")?.value ?? "";
  for (const r of item.references ?? []) {
    if (!r.url) continue;
    const tags = (r.tags ?? []).map((t) => t.toLowerCase());
    if (
      tags.includes("exploit") ||
      tags.includes("proof of concept") ||
      tags.includes("third party advisory")
    ) {
      return {
        ready: true,
        pocUrl: r.url,
        reason: `nvd reference tagged ${tags.join("|")}`,
      };
    }
    if (/exploit-db|github\.com.*\/(poc|exploits)|cve\.org/i.test(r.url)) {
      return {
        ready: true,
        pocUrl: r.url,
        reason: "reference URL looks like a PoC source",
      };
    }
  }
  if (PAYLOAD_HEURISTICS_RX.test(desc)) {
    return {
      ready: true,
      pocUrl: null,
      reason: "description mentions PoC / exploit / payload",
    };
  }
  return { ready: false, pocUrl: null, reason: "no PoC reference or marker" };
}

// --- proposal renderer ----------------------------------------------------

function getCwes(item: NvdCveItem): string[] {
  const out: string[] = [];
  for (const w of item.weaknesses ?? []) {
    for (const d of w.description ?? []) {
      if (d.value && /^CWE-\d+$/.test(d.value)) out.push(d.value);
    }
  }
  return [...new Set(out)];
}

function getCvssV3(item: NvdCveItem): {
  score: number | undefined;
  severity: string | undefined;
  vector: string | undefined;
} {
  const m = item.metrics?.cvssMetricV31?.[0] ?? item.metrics?.cvssMetricV30?.[0];
  return {
    score: m?.cvssData?.baseScore,
    severity: m?.cvssData?.baseSeverity,
    vector: m?.cvssData?.vectorString,
  };
}

function getEnDescription(item: NvdCveItem): string {
  return (
    (item.descriptions ?? []).find((d) => d.lang === "en")?.value ?? ""
  ).trim();
}

function shortTitle(item: NvdCveItem): string {
  const d = getEnDescription(item);
  // First sentence-ish, capped at 110 chars
  const s = d.split(/(?<=[.?!])\s+/)[0] ?? d;
  return s.replace(/\s+/g, " ").slice(0, 110);
}

function renderProposal(item: NvdCveItem): string {
  const cveId = item.id;
  const desc = getEnDescription(item);
  const cwes = getCwes(item);
  const category = guessCategory(cwes);
  const cvss = getCvssV3(item);
  const { severity, isHigh } = severityFromScore(cvss.score);
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const triage = isDetectionReady(item);
  const refs = (item.references ?? []).map((r) => r.url).filter(Boolean);
  const cpes = extractCpeStrings(item).slice(0, 6);

  const cveBlock = `  cve:\n    - "${cveId}"\n`;
  const cweBlock =
    cwes.length > 0
      ? `  cwe:\n${cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const externalBlock =
    refs.length > 0
      ? `  external:\n${refs
          .slice(0, 8)
          .map((u) => `    - "${u.replace(/"/g, "%22")}"`)
          .join("\n")}\n`
      : "";

  const actions = isHigh ? "    - block_input\n    - alert" : "    - alert";
  const titleSafe = shortTitle(item).replace(/"/g, '\\"');
  const descSafe = desc.replace(/\n+/g, " ").replace(/\s+/g, " ").trim();
  const cvssLine =
    cvss.score !== undefined
      ? `CVSS v3 ${cvss.score} (${cvss.severity ?? severity.toUpperCase()})`
      : "CVSS unscored";

  return `# ATR rule proposal -- generated by scripts/sync-nvd-ai.ts
# Source: NVD CVE ${cveId}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${titleSafe}"
id: ATR-DRAFT-${cveId}
rule_version: 1
status: draft
description: >
  NVD-tracked CVE ${cveId} (${cvssLine}).
  ${descSafe.slice(0, 600)}
author: "ATR Community (NVD sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severity}

references:
${cveBlock}${cweBlock}${externalBlock}

metadata_provenance:
  cve: nvd-sync
${cwes.length ? "  cwe: nvd-sync\n" : ""}
tags:
  category: ${category}
  subcategory: nvd-imported
  scan_target: mcp
  confidence: medium

agent_source:
  type: llm_io
  framework:
    - any
  provider:
    - any

detection:
  condition: any
  false_positives: []
  conditions:
    # TODO(human): fill in regex / pattern conditions derived from the
    # vendor advisory or proof-of-concept payload.
${triage.pocUrl ? `    # Candidate PoC URL: ${triage.pocUrl}` : "    # No PoC reference detected -- consult the NVD detail page."}
    []

response:
  actions:
${actions}
  notify:
    - security_team

test_cases:
  true_positives: []
  true_negatives: []

confidence: 60

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"

# === sync-nvd-ai.ts provenance ===
_nvd_sync:
  cve_id: "${cveId}"
  discovered_by: "NVD via sync-nvd-ai.ts"
  source: "https://nvd.nist.gov/vuln/detail/${cveId}"
  cvss_v3: ${cvss.score ?? "null"}
  cvss_severity: ${cvss.severity ? `"${cvss.severity}"` : "null"}
  cvss_vector: ${cvss.vector ? `"${cvss.vector}"` : "null"}
  cwes:
${cwes.length ? cwes.map((c) => `    - "${c}"`).join("\n") : "    []"}
  cpes:
${cpes.length ? cpes.map((c) => `    - '${c.replace(/'/g, "''")}'`).join("\n") : "    []"}
  nvd_published: ${item.published ? `"${item.published}"` : "null"}
  nvd_modified: ${item.lastModified ? `"${item.lastModified}"` : "null"}
  imported_at: "${new Date().toISOString()}"
`;
}

// --- NVD fetch with rate limiting -----------------------------------------

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchNvdPage(
  keyword: string,
  startIndex: number,
  sinceIso: string,
): Promise<{ resp: NvdResponse | null; rateLimited: boolean }> {
  const u = new URL(NVD_API_URL);
  u.searchParams.set("keywordSearch", keyword);
  u.searchParams.set("startIndex", String(startIndex));
  u.searchParams.set("resultsPerPage", "200");
  u.searchParams.set("pubStartDate", sinceIso);
  // NVD requires both start and end when filtering by date
  u.searchParams.set("pubEndDate", new Date().toISOString());

  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "atr-sync-nvd-ai",
  };
  if (API_KEY) headers["apiKey"] = API_KEY;

  let attempt = 0;
  // Up to 3 retries on 429 / 5xx
  while (attempt < 3) {
    const resp = await fetch(u.toString(), { headers });
    if (resp.status === 429 || resp.status === 503) {
      attempt++;
      const backoff = 1000 * Math.pow(2, attempt); // 2s, 4s, 8s
      if (VERBOSE)
        console.error(
          `NVD ${resp.status} on ${keyword} startIndex=${startIndex} -- backoff ${backoff}ms (attempt ${attempt}/3)`,
        );
      await sleep(backoff);
      continue;
    }
    if (!resp.ok) {
      if (VERBOSE)
        console.error(
          `NVD non-200 for ${keyword}: ${resp.status} ${resp.statusText}`,
        );
      return { resp: null, rateLimited: false };
    }
    const data = (await resp.json()) as NvdResponse;
    return { resp: data, rateLimited: false };
  }
  return { resp: null, rateLimited: true };
}

// NVD rate guidance: 5 req / 30 sec without key, 50 req / 30 sec with key.
// We pad slightly above guidance to avoid 429.
const REQUEST_DELAY_MS = API_KEY ? 700 : 6500;

async function fetchAllForKeyword(
  keyword: string,
  sinceIso: string,
  summary: NvdSyncSummary,
): Promise<NvdCveItem[]> {
  const all: NvdCveItem[] = [];
  let startIndex = 0;
  let total = Infinity;
  let pages = 0;

  while (startIndex < total) {
    pages++;
    await sleep(REQUEST_DELAY_MS);
    const { resp, rateLimited } = await fetchNvdPage(
      keyword,
      startIndex,
      sinceIso,
    );
    if (rateLimited) {
      summary.rate_limited = true;
      console.error(
        `aborting keyword '${keyword}' at startIndex=${startIndex} after 3 backoffs`,
      );
      break;
    }
    if (!resp) {
      summary.errors.push(
        `non-OK NVD response for keyword='${keyword}' startIndex=${startIndex}`,
      );
      break;
    }
    total = resp.totalResults;
    for (const v of resp.vulnerabilities ?? []) {
      all.push(v.cve);
    }
    summary.cves_queried += resp.vulnerabilities?.length ?? 0;
    if (VERBOSE)
      console.error(
        `  keyword='${keyword}' page=${pages} cves=${resp.vulnerabilities?.length ?? 0} / total=${total}`,
      );
    startIndex += resp.resultsPerPage;
    // Hard guard: never page more than 5000 results for one keyword
    if (startIndex >= 5000) {
      console.error(
        `  keyword='${keyword}' hit 5000-result guard; remaining results skipped`,
      );
      break;
    }
  }
  return all;
}

// --- summary shape --------------------------------------------------------

interface NvdSyncSummary {
  run_date: string;
  since: string;
  cves_queried: number;
  ai_relevant_count: number;
  new_proposals: number;
  skipped_existing: number;
  rate_limited: boolean;
  errors: string[];
  written_files: string[];
  new_detection_ready: number;
  new_tracking_only: number;
}

// --- main -----------------------------------------------------------------

function isoSince(): string {
  const fallback = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  if (!SINCE) return fallback.toISOString();
  const d = new Date(SINCE);
  if (isNaN(d.getTime())) {
    console.error(`--since '${SINCE}' is not a parseable date`);
    process.exit(1);
  }
  return d.toISOString();
}

async function main(): Promise<void> {
  if (!existsSync(PROPOSALS_DIR)) mkdirSync(PROPOSALS_DIR, { recursive: true });

  const sinceIso = isoSince();
  const cveIndex = buildCveIndex();
  const summary: NvdSyncSummary = {
    run_date: new Date().toISOString(),
    since: sinceIso,
    cves_queried: 0,
    ai_relevant_count: 0,
    new_proposals: 0,
    skipped_existing: 0,
    rate_limited: false,
    errors: [],
    written_files: [],
    new_detection_ready: 0,
    new_tracking_only: 0,
  };

  console.error(`=== sync-nvd-ai.ts ===`);
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  console.error(`since: ${sinceIso}`);
  console.error(`API key: ${API_KEY ? "set" : "not set (slow path)"}`);
  console.error(`existing ATR CVE index size: ${cveIndex.size}`);

  // De-dupe across keywords by CVE id
  const seen = new Set<string>();
  const collected: NvdCveItem[] = [];

  if (CVE_FILTER) {
    // Single-CVE fast path uses the cveId query param
    await sleep(REQUEST_DELAY_MS);
    const u = new URL(NVD_API_URL);
    u.searchParams.set("cveId", CVE_FILTER);
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": "atr-sync-nvd-ai",
    };
    if (API_KEY) headers["apiKey"] = API_KEY;
    const resp = await fetch(u.toString(), { headers });
    if (!resp.ok) {
      console.error(`single-CVE fetch failed: ${resp.status}`);
      process.exit(1);
    }
    const data = (await resp.json()) as NvdResponse;
    for (const v of data.vulnerabilities ?? []) collected.push(v.cve);
    summary.cves_queried = collected.length;
  } else {
    for (const kw of NVD_KEYWORDS) {
      if (summary.new_proposals >= LIMIT) break;
      const items = await fetchAllForKeyword(kw, sinceIso, summary);
      for (const item of items) {
        if (!seen.has(item.id)) {
          seen.add(item.id);
          collected.push(item);
        }
      }
      if (summary.rate_limited) break;
    }
  }

  console.error(
    `\nde-duped CVEs across keywords: ${collected.length} (queried events: ${summary.cves_queried})`,
  );

  for (const item of collected) {
    if (summary.new_proposals >= LIMIT) break;
    const rel = isAIRelevant(item);
    if (!rel.match) {
      if (VERBOSE) console.error(`  skip ${item.id}: ${rel.reason}`);
      continue;
    }
    summary.ai_relevant_count++;

    if (cveIndex.has(item.id) && !FORCE) {
      summary.skipped_existing++;
      if (VERBOSE)
        console.error(`  have ${item.id}: already in rules/ or proposals/`);
      continue;
    }

    const outPath = join(PROPOSALS_DIR, `${item.id}.proposal.yaml`);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing++;
      if (VERBOSE) console.error(`  have-file ${item.id}: ${outPath}`);
      continue;
    }

    const body = renderProposal(item);
    const triage = isDetectionReady(item);
    if (triage.ready) summary.new_detection_ready++;
    else summary.new_tracking_only++;

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
    }
    summary.new_proposals++;
    console.error(
      `  ${WRITE ? "wrote" : "would write"} ${item.id} -> ${outPath.replace(REPO_ROOT + "/", "")} ` +
        `(${rel.reason}; ${triage.ready ? "READY" : "TRACKING"})`,
    );
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::nvd-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      ai_relevant_count: summary.ai_relevant_count,
      cves_queried: summary.cves_queried,
      skipped_existing: summary.skipped_existing,
      rate_limited: summary.rate_limited,
    })}`,
  );

  if (summary.rate_limited) process.exit(2);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
