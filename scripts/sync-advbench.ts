#!/usr/bin/env npx tsx
/**
 * sync-advbench.ts
 *
 * Pulls three major academic adversarial-prompt benchmarks
 * (AdvBench, HarmBench, JailbreakBench) and emits ATR rule proposals
 * (proposals/<source>/<slug>.proposal.yaml) for each unique harmful
 * behavior, so a human reviewer can later supply the regex/LLM
 * detection condition.
 *
 * Why three corpora in one script?
 *   - Same data shape (behavior text + category label).
 *   - Same proposal shape (detection.conditions left empty as TODO).
 *   - Same dedupe key (SHA256 of prompt text, first 8 chars).
 *   - Same provenance pattern (full upstream URL + license).
 *   Keeping them in one orchestrated pass lets the cve-collect.ts
 *   wrapper treat "advbench" as a single SOURCES entry.
 *
 * Sources (all MIT or CC-BY licensed):
 *   - AdvBench       (llm-attacks/llm-attacks, MIT)
 *                    harmful_behaviors.csv -- 520 prompts
 *   - HarmBench      (centerforaisafety/HarmBench, MIT)
 *                    harmbench_behaviors_text_all.csv -- ~400 prompts
 *   - JailbreakBench (JailbreakBench/jailbreakbench, MIT)
 *                    data/behaviors.csv -- 100 prompts
 *
 * Each proposal includes:
 *   - skeleton with required schema fields (status=draft,
 *     maturity=experimental)
 *   - tags.category mapped from the source category label
 *   - tags.subcategory = jailbreak-academic-imported
 *   - test_cases.true_positives prepopulated with the prompt text
 *   - empty detection.conditions array with TODO marker
 *   - provenance block recording discovered_by, source URL,
 *     upstream_license, imported_at ISO timestamp,
 *     behavior_id_in_source
 *
 * The script is idempotent: if a rule already mentions the prompt
 * hash OR a proposal already exists at the target path, it's
 * skipped (unless --force).
 *
 * Usage:
 *   npx tsx scripts/sync-advbench.ts                          # dry-run all 3 sources
 *   npx tsx scripts/sync-advbench.ts --write                   # write proposals to disk
 *   npx tsx scripts/sync-advbench.ts --source advbench --write # one source only
 *   npx tsx scripts/sync-advbench.ts --force                   # re-render even if exists
 *
 * Exit codes:
 *   0 success
 *   1 fatal error (all sources unreachable)
 *   2 partial (some sources 404 / network failed but others worked)
 */

import {
  createHash,
} from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const PROPOSALS_BASE = resolve(REPO_ROOT, 'proposals');
const DATA_OUT_DIR = resolve(REPO_ROOT, 'data/cve-collector');
const DATA_OUT_FILE = join(DATA_OUT_DIR, 'advbench-last-run.json');

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag('--write');
const FORCE = flag('--force');
const VERBOSE = flag('--verbose');
const SOURCE_FILTER = opt('--source');

// --- source registry ------------------------------------------------------

type SourceId = 'advbench' | 'harmbench' | 'jailbreakbench';

interface SourceDef {
  id: SourceId;
  name: string;             // human-readable, used in title + provenance
  shortPrefix: string;      // ADVB / HARMB / JBB -- used in rule id
  url: string;              // raw CSV
  license: string;          // upstream license string
  proposalsSubdir: string;  // proposals/<subdir>/
  // The CSV column that holds the harmful prompt text.
  // For AdvBench/HarmBench/JBB this varies, so we resolve by header.
  behaviorColumns: string[];
  // The CSV column that holds the category label (used for tags.category map).
  categoryColumns: string[];
  // Optional behavior id column (for provenance traceability).
  idColumns: string[];
}

const SOURCES: SourceDef[] = [
  {
    id: 'advbench',
    name: 'AdvBench',
    shortPrefix: 'ADVB',
    url: 'https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv',
    license: 'MIT',
    proposalsSubdir: 'advbench',
    // AdvBench harmful_behaviors.csv columns: goal, target
    behaviorColumns: ['goal', 'behavior', 'prompt'],
    categoryColumns: ['category', 'topic', 'class'],
    idColumns: ['index', 'id', 'row'],
  },
  {
    id: 'harmbench',
    name: 'HarmBench',
    shortPrefix: 'HARMB',
    url: 'https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv',
    license: 'MIT',
    proposalsSubdir: 'harmbench',
    // HarmBench columns: Behavior, FunctionalCategory, SemanticCategory, BehaviorID, ContextString, Tags
    behaviorColumns: ['Behavior', 'behavior', 'goal'],
    categoryColumns: ['SemanticCategory', 'semantic_category', 'FunctionalCategory', 'functional_category', 'category'],
    idColumns: ['BehaviorID', 'behavior_id', 'id'],
  },
  {
    id: 'jailbreakbench',
    name: 'JailbreakBench',
    shortPrefix: 'JBB',
    // JailbreakBench ships its behaviors via HuggingFace, not the GitHub
    // main repo (only loader code lives in github.com/JailbreakBench/jailbreakbench).
    // We hit the HF resolve URL directly so the script stays dependency-free.
    url: 'https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main/data/harmful-behaviors.csv',
    license: 'MIT',
    proposalsSubdir: 'jailbreakbench',
    // JBB JBB-Behaviors columns: Behavior, Goal, Target, Category, Source, Index
    behaviorColumns: ['Goal', 'goal', 'Behavior', 'behavior', 'prompt'],
    categoryColumns: ['Category', 'category'],
    idColumns: ['Index', 'index', 'Behavior', 'behavior', 'id'],
  },
];

// --- source category -> ATR category map ----------------------------------
//
// Per task spec:
//   "Bombs/Weapons/Chemicals" / "Cybercrime/Intrusion" / "Harassment/Bullying"
//     / "Harmful" -> prompt-injection
//   "Misinformation/Disinformation" -> model-abuse
//   "Illegal/Drugs" / "Misc" -> prompt-injection
//
// We don't trust the upstream label to be precision-clean, so we match
// substrings case-insensitively rather than requiring exact equality.
// All unknown categories fall back to prompt-injection (safest default --
// the rule catches the *jailbreak* attempt, not the harmful output itself).

interface CategoryMatcher {
  pattern: RegExp;
  category: string;
}

const CATEGORY_RULES: CategoryMatcher[] = [
  { pattern: /\b(misinformation|disinformation|fake[- ]?news|propaganda|conspiracy)\b/i, category: 'model-abuse' },
  { pattern: /\b(bomb|weapon|chemical|biological|nuclear|firearm|explosive)\b/i, category: 'prompt-injection' },
  { pattern: /\b(cyber|malware|hack|intrusion|exploit|phishing|ransomware)\b/i, category: 'prompt-injection' },
  { pattern: /\b(harass|bully|threat|stalk|hate|abuse)\b/i, category: 'prompt-injection' },
  { pattern: /\b(harmful|harm|dangerous|toxic)\b/i, category: 'prompt-injection' },
  { pattern: /\b(illegal|drug|narcotic|fraud|theft|piracy)\b/i, category: 'prompt-injection' },
  { pattern: /\b(misc|other|miscellaneous|general)\b/i, category: 'prompt-injection' },
];

function mapCategory(sourceLabel: string): string {
  for (const r of CATEGORY_RULES) {
    if (r.pattern.test(sourceLabel)) return r.category;
  }
  return 'prompt-injection';
}

// --- CSV parser (handles quoted cells with embedded commas / newlines) ----

function parseCsv(text: string): { header: string[]; rows: string[][] } {
  // RFC 4180-ish parser. Handles:
  //   - "quoted" cells
  //   - embedded "" (escaped quote)
  //   - embedded \n inside quoted cells
  //   - CRLF and LF line endings
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuote = false;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (inQuote) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 2;
          continue;
        }
        inQuote = false;
        i++;
        continue;
      }
      cell += c;
      i++;
      continue;
    }
    if (c === '"') {
      inQuote = true;
      i++;
      continue;
    }
    if (c === ',') {
      row.push(cell);
      cell = '';
      i++;
      continue;
    }
    if (c === '\r') {
      i++;
      continue;
    }
    if (c === '\n') {
      row.push(cell);
      cell = '';
      rows.push(row);
      row = [];
      i++;
      continue;
    }
    cell += c;
    i++;
  }
  // Flush trailing cell/row.
  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  // Drop trailing empty rows.
  while (rows.length > 0 && rows[rows.length - 1].every((x) => x.trim() === '')) {
    rows.pop();
  }
  if (rows.length === 0) return { header: [], rows: [] };
  const header = rows.shift()!;
  return { header, rows };
}

function pickColumn(header: string[], candidates: string[]): number {
  for (const c of candidates) {
    const idx = header.findIndex((h) => h.trim().toLowerCase() === c.toLowerCase());
    if (idx >= 0) return idx;
  }
  return -1;
}

// --- hash / slug helpers --------------------------------------------------

function sha256Short(text: string): string {
  return createHash('sha256').update(text).digest('hex').slice(0, 8);
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^\w]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substring(0, 60);
}

// --- existing rule / proposal index ---------------------------------------

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
    else if (st.isFile() && (e.endsWith('.yaml') || e.endsWith('.yml'))) out.push(f);
  }
  return out;
}

// We treat a proposal as "already exists" if its id contains the same
// shortPrefix+hash, regardless of slug, so re-running with a slightly
// different prompt slug doesn't double-write. The id is `ATR-<PREFIX>-<HASH>`
// which is unique enough.
function buildExistingIdIndex(): Set<string> {
  const ix = new Set<string>();
  const rulePaths = walkYaml(RULES_DIR);
  const proposalPaths = walkYaml(PROPOSALS_BASE);
  for (const f of [...rulePaths, ...proposalPaths]) {
    let raw: string;
    try {
      raw = readFileSync(f, 'utf-8');
    } catch {
      continue;
    }
    let doc: unknown;
    try {
      doc = yaml.load(raw);
    } catch {
      continue;
    }
    const obj = doc as { id?: string };
    if (obj?.id && typeof obj.id === 'string') ix.add(obj.id);
  }
  return ix;
}

// --- proposal renderer ----------------------------------------------------

function renderProposal(args: {
  source: SourceDef;
  prompt: string;
  category: string;        // already-mapped ATR category
  sourceCategory: string;  // raw upstream label, for description
  hash: string;
  behaviorIdInSource: string;
}): string {
  const { source, prompt, category, sourceCategory, hash, behaviorIdInSource } = args;
  const titleHead = sourceCategory.trim() || 'Adversarial behavior';
  const titleTail = prompt.length > 60 ? prompt.slice(0, 60).trim() + '...' : prompt.trim();
  const title = `[${source.name}] ${titleHead}: ${titleTail}`.replace(/\s+/g, ' ');
  const safeTitle = title.replace(/"/g, '\\"');

  const id = `ATR-${source.shortPrefix}-${hash}`;
  const today = new Date();
  const dateSlash = today.toISOString().slice(0, 10).replace(/-/g, '/');
  const isoNow = today.toISOString();

  // Escape prompt for YAML single-line string (we use the test_cases.input
  // field, which accepts arbitrary strings via folded/quoted YAML).
  // We pick a YAML literal block scalar to avoid quoting hell.
  const promptIndented = prompt
    .replace(/\r/g, '')
    .split('\n')
    .map((line) => `        ${line}`)
    .join('\n');

  return `# ATR rule proposal -- generated by scripts/sync-advbench.ts
# Source: ${source.name} (${source.url})
# Imported on: ${today.toISOString().slice(0, 10)}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge.
title: "${safeTitle}"
id: ${id}
rule_version: 1
status: draft
description: >
  Auto-imported harmful behavior from the ${source.name} academic adversarial
  prompt benchmark (upstream category: ${sourceCategory || 'unspecified'}).
  The benchmark records this prompt as a jailbreak target -- the rule below is
  meant to detect *attempts to elicit this behavior*, not the harmful output
  itself. detection.conditions are intentionally left empty: a human reviewer
  must inspect the source prompt and craft a precision-safe regex or
  LLM-classifier condition (see existing prompt-injection rules for examples).
author: "ATR Community (academic benchmark sync)"
date: "${dateSlash}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: high

references:
  external:
    - "${source.url}"

metadata_provenance:
  discovered_by: "${source.name}"
  source: "${source.url}"
  upstream_license: "${source.license}"
  imported_at: "${isoNow}"
  behavior_id_in_source: "${behaviorIdInSource.replace(/"/g, '\\"')}"
  prompt_sha256_short: "${hash}"

tags:
  category: ${category}
  subcategory: jailbreak-academic-imported
  scan_target: llm
  confidence: low

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
    # TODO(human): fill in regex / LLM-classifier conditions derived from
    # the prompt text below. The raw benchmark prompt alone is not a
    # precision-safe pattern; a human must generalize it.
    []

response:
  actions:
    - block_input
    - alert
  notify:
    - security_team

test_cases:
  true_positives:
    - input: |
${promptIndented}
      expected: triggered
  true_negatives:
    # TODO(human): add benign phrasings of the same surface words to
    # validate that the rule doesn't over-trigger on educational /
    # research / news framings of the topic.
    []
`;
}

// --- per-source pipeline --------------------------------------------------

interface SourceRunResult {
  id: SourceId;
  url: string;
  fetched_ok: boolean;
  rows_total: number;
  rows_with_prompt: number;
  written: number;
  skipped_already_exists: number;
  errors: string[];
  written_paths: string[];
  http_status?: number;
}

async function fetchCsv(url: string): Promise<{ status: number; body: string | null }> {
  try {
    const res = await fetch(url);
    if (!res.ok) {
      return { status: res.status, body: null };
    }
    return { status: res.status, body: await res.text() };
  } catch (err) {
    return { status: -1, body: null };
  }
}

function ensureDir(p: string): void {
  if (!existsSync(p)) mkdirSync(p, { recursive: true });
}

async function processSource(
  s: SourceDef,
  existingIds: Set<string>,
): Promise<SourceRunResult> {
  const result: SourceRunResult = {
    id: s.id,
    url: s.url,
    fetched_ok: false,
    rows_total: 0,
    rows_with_prompt: 0,
    written: 0,
    skipped_already_exists: 0,
    errors: [],
    written_paths: [],
  };

  console.log(`\n--- ${s.name} (${s.id}) ---`);
  const fetched = await fetchCsv(s.url);
  result.http_status = fetched.status;
  if (!fetched.body) {
    const msg = `${s.name}: fetch failed (HTTP ${fetched.status}) -- skipping source`;
    console.warn(`  ${msg}`);
    result.errors.push(msg);
    return result;
  }
  result.fetched_ok = true;

  const { header, rows } = parseCsv(fetched.body);
  if (header.length === 0) {
    const msg = `${s.name}: CSV empty or unparseable -- skipping`;
    console.warn(`  ${msg}`);
    result.errors.push(msg);
    return result;
  }
  result.rows_total = rows.length;

  const promptCol = pickColumn(header, s.behaviorColumns);
  const categoryCol = pickColumn(header, s.categoryColumns);
  const idCol = pickColumn(header, s.idColumns);

  if (promptCol < 0) {
    const msg = `${s.name}: no behavior column found (looked for ${s.behaviorColumns.join('/')}); header was ${header.join('|')}`;
    console.warn(`  ${msg}`);
    result.errors.push(msg);
    return result;
  }
  if (VERBOSE) {
    console.log(`  header: ${header.join(' | ')}`);
    console.log(`  prompt column: ${header[promptCol]} (index ${promptCol})`);
    if (categoryCol >= 0) console.log(`  category column: ${header[categoryCol]} (index ${categoryCol})`);
    else console.log('  category column: (not found, falling back to prompt-injection)');
  }

  const proposalsDir = resolve(PROPOSALS_BASE, s.proposalsSubdir);
  if (WRITE) ensureDir(proposalsDir);

  const seenHashesThisRun = new Set<string>();
  let rowIdx = 0;
  for (const row of rows) {
    rowIdx++;
    const prompt = (row[promptCol] || '').trim();
    if (!prompt) continue;
    result.rows_with_prompt++;
    const hash = sha256Short(prompt);
    if (seenHashesThisRun.has(hash)) {
      // Same prompt appeared twice in this CSV (e.g. JBB Behaviors).
      continue;
    }
    seenHashesThisRun.add(hash);
    const id = `ATR-${s.shortPrefix}-${hash}`;
    if (existingIds.has(id) && !FORCE) {
      result.skipped_already_exists++;
      if (VERBOSE) console.log(`    skip ${id}: already exists`);
      continue;
    }
    const sourceCategory = categoryCol >= 0 ? (row[categoryCol] || '').trim() : '';
    const category = mapCategory(sourceCategory);
    const behaviorIdInSource = idCol >= 0
      ? (row[idCol] || `row-${rowIdx}`).trim()
      : `row-${rowIdx}`;
    const slug = slugify(`${sourceCategory || 'behavior'}-${prompt}`) || hash;
    const targetName = `${id}-${slug}.proposal.yaml`;
    const target = join(proposalsDir, targetName);

    // Skip if a file with the same id already exists (different slug),
    // unless --force.
    const existingFiles = WRITE && existsSync(proposalsDir)
      ? readdirSync(proposalsDir).filter((f) => f.startsWith(`${id}-`) || f === `${id}.proposal.yaml`)
      : [];
    if (existingFiles.length > 0 && !FORCE) {
      result.skipped_already_exists++;
      existingIds.add(id);
      if (VERBOSE) console.log(`    skip ${id}: proposal file already present`);
      continue;
    }

    const body = renderProposal({
      source: s,
      prompt,
      category,
      sourceCategory,
      hash,
      behaviorIdInSource,
    });

    if (WRITE) {
      writeFileSync(target, body, 'utf-8');
      result.written_paths.push(target);
    }
    existingIds.add(id);
    result.written++;
    if (VERBOSE || result.written <= 3) {
      console.log(`    ${WRITE ? 'wrote' : 'would write'} ${id} (${sourceCategory || 'no-cat'} -> ${category})`);
    }
  }

  console.log(
    `  ${s.name}: ${result.rows_total} rows, ${result.rows_with_prompt} usable, ` +
      `${WRITE ? 'wrote' : 'would-write'} ${result.written}, skipped ${result.skipped_already_exists}`,
  );
  return result;
}

// --- main ----------------------------------------------------------------

async function main(): Promise<void> {
  console.log('=== sync-advbench.ts ===');
  console.log(`mode: ${WRITE ? 'WRITE' : 'dry-run'}`);
  if (SOURCE_FILTER) console.log(`source filter: ${SOURCE_FILTER}`);
  if (FORCE) console.log('force: re-rendering existing proposals');

  const wanted = SOURCE_FILTER
    ? SOURCES.filter((s) => s.id === SOURCE_FILTER)
    : SOURCES;
  if (wanted.length === 0) {
    console.error(
      `unknown source "${SOURCE_FILTER}" -- known: ${SOURCES.map((s) => s.id).join(', ')}`,
    );
    process.exit(1);
  }

  const existingIds = buildExistingIdIndex();
  console.log(`existing ATR rules+proposals: ${existingIds.size} unique ids`);

  const perSource: SourceRunResult[] = [];
  for (const s of wanted) {
    const r = await processSource(s, existingIds);
    perSource.push(r);
  }

  if (WRITE) ensureDir(DATA_OUT_DIR);

  const totalWritten = perSource.reduce((a, r) => a + r.written, 0);
  const totalSkipped = perSource.reduce((a, r) => a + r.skipped_already_exists, 0);
  const totalRows = perSource.reduce((a, r) => a + r.rows_total, 0);
  const anyFetchFailed = perSource.some((r) => !r.fetched_ok);
  const allFetchFailed = perSource.every((r) => !r.fetched_ok);

  const report = {
    run_date: new Date().toISOString(),
    mode: WRITE ? 'write' : 'dry-run',
    force: FORCE,
    sources: perSource,
    totals: {
      rows_seen: totalRows,
      written: totalWritten,
      skipped_already_exists: totalSkipped,
      sources_succeeded: perSource.filter((r) => r.fetched_ok).length,
      sources_failed: perSource.filter((r) => !r.fetched_ok).length,
    },
  };

  if (WRITE) {
    writeFileSync(DATA_OUT_FILE, JSON.stringify(report, null, 2), 'utf-8');
  }

  console.log('');
  console.log('=== summary ===');
  for (const r of perSource) {
    const status = r.fetched_ok ? 'OK' : `FAIL(${r.http_status ?? '?'})`;
    console.log(
      `  ${r.id.padEnd(15)} ${status.padEnd(10)} ` +
        `rows=${r.rows_total} written=${r.written} skipped=${r.skipped_already_exists}`,
    );
  }
  console.log('');
  console.log(`total ${WRITE ? 'written' : 'would-write'}: ${totalWritten}`);
  console.log(`total skipped (already exist):   ${totalSkipped}`);
  if (WRITE) console.log(`report written to: ${DATA_OUT_FILE.replace(REPO_ROOT + '/', '')}`);

  // Marker line so cve-collect.ts orchestrator can parse our summary.
  const marker = {
    written: totalWritten,
    skipped: totalSkipped,
    sources_succeeded: report.totals.sources_succeeded,
    sources_failed: report.totals.sources_failed,
  };
  console.log(`::advbench-summary::${JSON.stringify(marker)}`);

  if (allFetchFailed) process.exit(1);
  if (anyFetchFailed) process.exit(2);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
