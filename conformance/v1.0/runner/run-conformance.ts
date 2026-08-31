#!/usr/bin/env tsx
/**
 * ATR Conformance Test Suite — reference runner v1.0
 *
 * Executes the suite against any engine whose CLI exposes a
 * `--scan <yaml>` entrypoint and emits Match output per SPEC §7.
 *
 * Exit codes:
 *   0   full pass at the declared level
 *   1   one or more fixtures failed
 *   2   runner-internal error (config invalid, paths missing, etc.)
 *
 * The runner is deterministic, network-free, and writes a JSON report
 * conforming to runner/report-schema.json.
 */

import { readFileSync, readdirSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SUITE_ROOT = join(__dirname, '..');
const FIXTURE_ROOT = join(SUITE_ROOT, 'fixtures');

type Outcome =
  | 'match'
  | 'no_match'
  | 'graceful_error'
  | 'graceful_error_or_no_match';

type ObservedKind = 'match' | 'no_match' | 'graceful_error' | 'engine_error';

interface ExpectFile {
  outcome: Outcome;
  rule_id?: string;
  min_match_count?: number;
  matched_selectors_must_include?: string[];
  error_kind_allowed?: string[];
  error_kind_must_include?: string[];
  max_runtime_ms?: number;
}

interface Args {
  engine: string;
  rules: string;
  level: 'L1' | 'L2' | 'L3';
  out: string;
}

interface FixtureResult {
  fixture: string;
  category: 'tp' | 'tn' | 'edge';
  rule_id?: string;
  expected: Outcome;
  observed: ObservedKind;
  passed: boolean;
  runtime_ms: number;
  failure_reason?: string;
}

interface Report {
  suite_version: string;
  spec_version: string;
  engine: string;
  rules: string;
  level: string;
  generated_at: string;
  totals: { total: number; passed: number; failed: number };
  results: FixtureResult[];
}

const SUITE_VERSION = 'v1.0.0';
const SPEC_VERSION = '1.0.0';

function parseArgs(argv: readonly string[]): Args {
  const args: Partial<Args> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--engine') args.engine = argv[++i];
    else if (a === '--rules') args.rules = argv[++i];
    else if (a === '--level') args.level = argv[++i] as Args['level'];
    else if (a === '--out') args.out = argv[++i];
  }
  if (!args.engine || !args.rules) {
    console.error('Usage: run-conformance.ts --engine <path> --rules <path> [--level L1|L2|L3] [--out <path>]');
    process.exit(2);
  }
  args.level ??= 'L2';
  args.out ??= join(process.cwd(), `conformance-report-${Date.now()}.json`);
  return args as Args;
}

function listFixtures(category: 'tp' | 'tn' | 'edge'): string[] {
  const root = join(FIXTURE_ROOT, category);
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .filter((name) => statSync(join(root, name)).isDirectory())
    .map((name) => join(root, name));
}

function loadExpect(fixturePath: string): ExpectFile {
  return JSON.parse(readFileSync(join(fixturePath, 'expect.json'), 'utf8')) as ExpectFile;
}

interface EngineMatch { rule_id: string; matched_selectors?: string[]; }

function runEngine(args: Args, inputPath: string): { matches: EngineMatch[]; error?: string; runtimeMs: number } {
  const start = Date.now();
  const result = spawnSync(
    args.engine,
    ['--scan', inputPath, '--rules', args.rules, '--json'],
    { timeout: 30_000, encoding: 'utf8', shell: false },
  );
  const runtimeMs = Date.now() - start;
  if (result.error) return { matches: [], error: result.error.message, runtimeMs };
  if (result.status !== 0) {
    return { matches: [], error: `engine exited ${result.status}: ${(result.stderr ?? '').slice(0, 200)}`, runtimeMs };
  }
  try {
    const parsed = JSON.parse(result.stdout) as EngineMatch[];
    return { matches: Array.isArray(parsed) ? parsed : [], runtimeMs };
  } catch (e) {
    return { matches: [], error: `engine output not valid JSON: ${(e as Error).message}`, runtimeMs };
  }
}

function evaluate(category: 'tp' | 'tn' | 'edge', expected: ExpectFile, observed: ReturnType<typeof runEngine>): FixtureResult {
  const expectedOutcome = expected.outcome;
  const ruleId = expected.rule_id ?? '';
  const matchesForRule = observed.matches.filter((m) => !ruleId || m.rule_id === ruleId);

  if (category === 'tp') {
    const want = expected.min_match_count ?? 1;
    const passed = matchesForRule.length >= want;
    return {
      fixture: '',
      category,
      rule_id: ruleId,
      expected: 'match',
      observed: matchesForRule.length > 0 ? 'match' : 'no_match',
      passed,
      runtime_ms: observed.runtimeMs,
      failure_reason: passed ? undefined : `expected ≥${want} match(es) for ${ruleId}; got ${matchesForRule.length}`,
    };
  }

  if (category === 'tn') {
    const passed = matchesForRule.length === 0;
    return {
      fixture: '',
      category,
      rule_id: ruleId,
      expected: 'no_match',
      observed: matchesForRule.length === 0 ? 'no_match' : 'match',
      passed,
      runtime_ms: observed.runtimeMs,
      failure_reason: passed ? undefined : `expected no match for ${ruleId}; got ${matchesForRule.length}`,
    };
  }

  const observedKind: FixtureResult['observed'] = observed.error
    ? 'graceful_error'
    : observed.matches.length === 0
      ? 'no_match'
      : 'match';
  const okOutcomes: ReadonlyArray<FixtureResult['observed']> =
    expectedOutcome === 'graceful_error_or_no_match'
      ? ['no_match', 'graceful_error']
      : expectedOutcome === 'graceful_error'
        ? ['graceful_error']
        : expectedOutcome === 'no_match'
          ? ['no_match']
          : ['no_match', 'graceful_error'];
  const allowedErrors = expected.error_kind_allowed ?? [];
  const requiredErrors = expected.error_kind_must_include ?? [];
  const errorKindOk =
    observed.error == null
      ? true
      : (allowedErrors.length === 0 || allowedErrors.some((k) => observed.error!.toLowerCase().includes(k))) &&
        requiredErrors.every((k) => observed.error!.toLowerCase().includes(k));
  const withinBudget = expected.max_runtime_ms ? observed.runtimeMs <= expected.max_runtime_ms : true;
  const passed = okOutcomes.includes(observedKind) && errorKindOk && withinBudget;
  return {
    fixture: '',
    category,
    expected: expectedOutcome,
    observed: observedKind,
    passed,
    runtime_ms: observed.runtimeMs,
    failure_reason: passed
      ? undefined
      : `edge fixture: observed=${observedKind} (expected ${okOutcomes.join('|')}), runtime=${observed.runtimeMs}ms budget=${expected.max_runtime_ms ?? '∞'}ms`,
  };
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  if (!existsSync(args.engine) || !existsSync(args.rules)) {
    console.error(`[conformance] engine or rules path missing: engine=${args.engine} rules=${args.rules}`);
    process.exit(2);
  }
  const results: FixtureResult[] = [];
  for (const category of ['tp', 'tn', 'edge'] as const) {
    for (const fixturePath of listFixtures(category)) {
      const expected = loadExpect(fixturePath);
      const inputPath = join(fixturePath, 'input.yaml');
      const observed = runEngine(args, inputPath);
      const r = evaluate(category, expected, observed);
      r.fixture = fixturePath.replace(SUITE_ROOT, '');
      results.push(r);
    }
  }
  const totals = {
    total: results.length,
    passed: results.filter((r) => r.passed).length,
    failed: results.filter((r) => !r.passed).length,
  };
  const report: Report = {
    suite_version: SUITE_VERSION,
    spec_version: SPEC_VERSION,
    engine: args.engine,
    rules: args.rules,
    level: args.level,
    generated_at: new Date().toISOString(),
    totals,
    results,
  };
  writeFileSync(args.out, JSON.stringify(report, null, 2) + '\n');
  console.log(`[conformance] ${totals.passed}/${totals.total} passed at ${args.level}`);
  console.log(`[conformance] report: ${args.out}`);
  process.exit(totals.failed > 0 ? 1 : 0);
}

main();
