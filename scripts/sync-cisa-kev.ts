#!/usr/bin/env npx tsx
/**
 * sync-cisa-kev.ts
 *
 * Pulls the CISA Known Exploited Vulnerabilities catalog and emits ATR rule
 * proposals (proposals/cisa-kev/<CVE-ID>.proposal.yaml) for any entry that
 * looks AI/agent/LLM-relevant.
 *
 * Heuristics for "AI-relevant":
 *  - vendorProject matches the AI-vendor allow-list (BerriAI, OpenAI, etc.)
 *  - OR product matches the AI-product regex
 *  - OR shortDescription explicitly mentions LLM / agent / MCP / prompt
 *    injection / vector store / RAG / embedding
 *
 * Microsoft / Google / NVIDIA / Amazon / Meta are filtered OUT unless they
 * also satisfy the product or description match -- otherwise we drag in
 * every Windows / Chromium / Tegra / IAM / WordPress kernel CVE.
 *
 * Each proposal includes:
 *  - skeleton with required schema fields (status=draft, maturity=experimental)
 *  - references.cve, references.cwe pre-filled from KEV
 *  - tags.category guessed from CWE family
 *  - empty detection.conditions array so the human author has to fill them
 *  - provenance block recording when / which catalogVersion this came from
 *
 * The script is idempotent: if a rule already references the CVE OR a
 * proposal already exists, it's skipped (unless --force).
 *
 * Usage:
 *   npx tsx scripts/sync-cisa-kev.ts                 # dry-run -- print summary
 *   npx tsx scripts/sync-cisa-kev.ts --write          # write proposals to disk
 *   npx tsx scripts/sync-cisa-kev.ts --since 2026-01  # only consider entries
 *                                                    # added on/after that date
 *   npx tsx scripts/sync-cisa-kev.ts --cve CVE-2026-42208  # single CVE
 *
 * Exit codes:
 *   0  success (n proposals would be / were written)
 *   1  fatal error (network, schema mismatch, etc.)
 */

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const PROPOSALS_DIR = resolve(REPO_ROOT, 'proposals/cisa-kev');

const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(name);
const opt = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag('--write');
const FORCE = flag('--force');
const SINCE = opt('--since'); // YYYY-MM or YYYY-MM-DD
const CVE_FILTER = opt('--cve');
const VERBOSE = flag('--verbose');

// --- AI relevance heuristics ------------------------------------------------

const AI_VENDORS = new Set(
  [
    'berriai',
    'openai',
    'anthropic',
    'huggingface',
    'hugging face',
    'langchain',
    'langchain-ai',
    'llamaindex',
    'cohere',
    'mistral',
    'mistral ai',
    'fireworks',
    'replicate',
    'together',
    'together ai',
    'pinecone',
    'weaviate',
    'qdrant',
    'chroma',
    'milvus',
    'vllm',
    'ollama',
    'lm studio',
    'jan',
    'transformers',
    'gradio',
    'streamlit',
    'autogpt',
    'babyagi',
    'crewai',
    'autogen',
    'goose',
    'cursor',
    'continue',
    'cody',
    'tabby',
  ].map((s) => s.toLowerCase()),
);

// Tight enough to skip false positives like "Exim Mail Transfer Agent",
// "Veritas Backup Exec Agent", "Windows SmartScreen Prompt", and OLE
// (Object Linking & Embedding) being mistaken for vector embeddings.
// AI vendors with "agent" / "prompt" / "skill" in their product name still
// match via the AI_VENDORS allow-list above.
const AI_PRODUCT_RX =
  /(?:^|\W)(?:llm|ai[- ]agent|autonomous[- ]agent|copilot|semantic[- ]kernel|langchain|llamaindex|vllm|gpt|claude|llama|gemini|mistral|chatgpt|chatbot|model[- ]context[- ]protocol|mcp\b|vector[- ]store|huggingface|transformers)(?:\W|$)/i;

const AI_DESC_RX =
  /\b(?:llm|large language model|generative ai|gen[- ]?ai|ai agent|autonomous agent|prompt injection|tool poisoning|model context protocol|\bmcp\b|vector store|vector embedding|embedding model|skill\.md|claude\.md|cursor[- ]rules?|copilot|chatgpt|gpt-?[0-9])\b/i;

function isAIRelevant(entry: KevEntry): { match: boolean; reason: string } {
  const vendor = (entry.vendorProject || '').toLowerCase();
  const product = (entry.product || '').toLowerCase();
  const desc = (entry.shortDescription || '').toLowerCase();

  if (AI_VENDORS.has(vendor)) {
    return { match: true, reason: `vendor=${vendor} on allow-list` };
  }
  if (AI_PRODUCT_RX.test(product)) {
    return { match: true, reason: `product=${entry.product} matches AI_PRODUCT_RX` };
  }
  if (AI_DESC_RX.test(desc)) {
    return { match: true, reason: 'description has AI/agent terms' };
  }
  return { match: false, reason: 'no AI/agent signal' };
}

// --- CWE -> ATR category guess ---------------------------------------------

const CWE_TO_CATEGORY: Record<string, string> = {
  'CWE-89': 'data-poisoning', // SQL injection
  'CWE-78': 'tool-poisoning', // OS command injection -- tool side
  'CWE-94': 'agent-manipulation', // code injection / eval
  'CWE-95': 'agent-manipulation', // eval
  'CWE-77': 'tool-poisoning',
  'CWE-22': 'context-exfiltration', // path traversal
  'CWE-79': 'prompt-injection', // XSS in LLM output
  'CWE-352': 'agent-manipulation', // CSRF
  'CWE-918': 'context-exfiltration', // SSRF
  'CWE-200': 'context-exfiltration', // info exposure
  'CWE-502': 'tool-poisoning', // deserialization
  'CWE-269': 'privilege-escalation',
  'CWE-863': 'privilege-escalation',
  'CWE-732': 'privilege-escalation',
  'CWE-639': 'privilege-escalation', // IDOR
  'CWE-287': 'privilege-escalation', // auth bypass
  'CWE-732': 'privilege-escalation',
  'CWE-862': 'privilege-escalation',
};

function guessCategory(cwes: string[]): string {
  for (const cwe of cwes) {
    if (CWE_TO_CATEGORY[cwe]) return CWE_TO_CATEGORY[cwe];
  }
  return 'model-abuse'; // catch-all
}

// --- KEV entry shape -------------------------------------------------------

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
  cwes?: string[];
}

interface KevCatalog {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

// --- existing rule lookup --------------------------------------------------

function walkYaml(dir: string): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    const st = statSync(f);
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && e.endsWith('.yaml')) out.push(f);
  }
  return out;
}

function buildCveIndex(): Set<string> {
  const ix = new Set<string>();
  for (const f of walkYaml(RULES_DIR)) {
    let raw: string;
    try {
      raw = readFileSync(f, 'utf-8');
    } catch {
      continue;
    }
    let doc: any;
    try {
      doc = yaml.load(raw);
    } catch {
      continue;
    }
    const cves = doc?.references?.cve;
    if (Array.isArray(cves)) for (const c of cves) ix.add(c);
  }
  return ix;
}

// --- proposal renderer -----------------------------------------------------

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^\w]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substring(0, 60);
}

function renderProposal(entry: KevEntry, catalogVersion: string): string {
  const category = guessCategory(entry.cwes || []);
  const cwes = (entry.cwes || []).map((c) => `    - "${c}"`).join('\n') || '    []';
  const cveNotes = entry.notes ? entry.notes.split(';').map((s) => s.trim()) : [];
  const refLinks = cveNotes.filter((s) => s.startsWith('http'));

  return `# ATR rule proposal -- generated by scripts/sync-cisa-kev.ts
# Source: CISA KEV catalog version ${catalogVersion}
# Imported on: ${new Date().toISOString().slice(0, 10)}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge.
title: "${entry.vulnerabilityName.replace(/"/g, '\\"')}"
id: ATR-DRAFT-${entry.cveID}
rule_version: 1
status: draft
description: >
  CISA KEV-tracked exploited vulnerability (${entry.cveID}).
  ${entry.shortDescription.replace(/\n+/g, ' ').trim()}
author: "ATR Community (CISA KEV sync)"
date: "${new Date().toISOString().slice(0, 10).replace(/-/g, '/')}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${entry.cwes?.includes('CWE-94') || entry.cwes?.includes('CWE-78') ? 'critical' : 'high'}

references:
  cve:
    - "${entry.cveID}"
  cwe:
${cwes}
${refLinks.length ? '  external:\n' + refLinks.map((u) => `    - "${u}"`).join('\n') : ''}

metadata_provenance:
  cve: cisa-kev-sync
  cwe: cisa-kev-sync

tags:
  category: ${category}
  scan_target: runtime
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
    # vendor advisory or proof-of-concept payload. The CISA short description
    # alone is not sufficient to produce a precision-safe pattern.
    []

response:
  actions:
    - alert
  notify:
    - security_team

remediation: >
  See vendor advisory at the URL(s) listed under references.external.
  CISA-mandated remediation deadline: ${entry.dueDate || 'see KEV entry'}.
  ${entry.requiredAction ? entry.requiredAction.replace(/\n+/g, ' ').trim() : ''}

test_cases:
  true_positives: []
  true_negatives: []

# === sync-cisa-kev.ts provenance ===
_cisa_kev_sync:
  catalog_version: "${catalogVersion}"
  vendor: "${entry.vendorProject.replace(/"/g, '\\"')}"
  product: "${entry.product.replace(/"/g, '\\"')}"
  date_added_to_kev: "${entry.dateAdded}"
  known_ransomware_use: ${entry.knownRansomwareCampaignUse || '"Unknown"'}
`;
}

// --- main ------------------------------------------------------------------

async function fetchCatalog(): Promise<KevCatalog> {
  const res = await fetch(CISA_KEV_URL);
  if (!res.ok) throw new Error(`CISA KEV fetch failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as KevCatalog;
}

function isOnOrAfter(dateAdded: string, since: string | undefined): boolean {
  if (!since) return true;
  return dateAdded >= since;
}

async function main() {
  console.log('=== sync-cisa-kev.ts ===');
  console.log(`mode: ${WRITE ? 'WRITE' : 'dry-run'}`);
  if (SINCE) console.log(`since: ${SINCE}`);
  if (CVE_FILTER) console.log(`single CVE: ${CVE_FILTER}`);

  const catalog = await fetchCatalog();
  console.log(
    `loaded CISA KEV ${catalog.catalogVersion} -- ${catalog.count} entries, released ${catalog.dateReleased.slice(0, 10)}`,
  );

  const cveIndex = buildCveIndex();
  console.log(`existing ATR rules cover ${cveIndex.size} unique CVEs`);

  if (WRITE && !existsSync(PROPOSALS_DIR)) mkdirSync(PROPOSALS_DIR, { recursive: true });

  let scanned = 0;
  let aiRelevant = 0;
  let alreadyHaveRule = 0;
  let alreadyHaveProposal = 0;
  let written = 0;
  const writtenList: string[] = [];

  for (const entry of catalog.vulnerabilities) {
    if (CVE_FILTER && entry.cveID !== CVE_FILTER) continue;
    if (!isOnOrAfter(entry.dateAdded, SINCE)) continue;
    scanned++;
    const r = isAIRelevant(entry);
    if (!r.match) {
      if (VERBOSE) console.log(`  skip ${entry.cveID}: ${r.reason}`);
      continue;
    }
    aiRelevant++;
    if (cveIndex.has(entry.cveID) && !FORCE) {
      alreadyHaveRule++;
      if (VERBOSE) console.log(`  have-rule ${entry.cveID}: covered by existing rule`);
      continue;
    }
    const target = join(PROPOSALS_DIR, `${entry.cveID}-${slugify(entry.product)}.proposal.yaml`);
    if (existsSync(target) && !FORCE) {
      alreadyHaveProposal++;
      if (VERBOSE) console.log(`  have-proposal ${entry.cveID}: ${target}`);
      continue;
    }
    const body = renderProposal(entry, catalog.catalogVersion);
    if (WRITE) {
      writeFileSync(target, body, 'utf-8');
      writtenList.push(target);
    }
    written++;
    console.log(`  ${WRITE ? 'wrote' : 'would write'} ${entry.cveID} -> ${target}`);
    console.log(`     vendor=${entry.vendorProject} product=${entry.product}`);
    console.log(`     reason: ${r.reason}`);
  }

  console.log('');
  console.log('=== summary ===');
  console.log(`scanned:             ${scanned}`);
  console.log(`AI-relevant:         ${aiRelevant}`);
  console.log(`already in ATR:      ${alreadyHaveRule}`);
  console.log(`already in proposals:${alreadyHaveProposal}`);
  console.log(`${WRITE ? 'written' : 'would-write'}: ${written}`);

  if (WRITE && writtenList.length > 0) {
    console.log('');
    console.log('Next steps:');
    console.log('  1. cd proposals/cisa-kev && open <CVE>.proposal.yaml');
    console.log('  2. Fill in detection.conditions[] from vendor advisory / PoC');
    console.log('  3. Add test_cases.true_positives + test_cases.true_negatives');
    console.log('  4. Reassign an ATR-2026-NNNNN id (scripts/next-rule-id.ts)');
    console.log('  5. Move file to rules/<category>/ and remove _cisa_kev_sync block');
    console.log('  6. npx tsx scripts/check-rules-safety.ts');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
